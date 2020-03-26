#  Copyright  2020 Alexis Lopez Zubieta
#
#  Permission is hereby granted, free of charge, to any person obtaining a
#  copy of this software and associated documentation files (the "Software"),
#  to deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
import hashlib
import logging
import os

import requests

from AppImageBuilder.commands.apt_key import AptKey
from AppImageBuilder.commands.dpkg_architecture import DpkgArchitecture


class AptConfigError(RuntimeError):
    pass


class Config:
    def __init__(self, apt_root):
        self.settings = {}

        self.apt_prefix = apt_root
        self.apt_conf_path = None
        self.apt_source_lines = []
        self.apt_source_key_urls = []
        self.apt_include = []
        self.apt_exclude = []

    def load(self, settings):
        self.settings = settings

        self._load_arch()
        self._load_sources()
        self._load_apt_includes()
        self._load_apt_excludes()

    def generate(self):
        self._generate_apt_work_dirs()
        self._generate_apt_conf()
        self._generate_apt_source_list()
        self._generate_apt_keyring()
        self._generate_dpkg_arch()
        self._generate_dpkg_status()

    def _load_arch(self):
        if 'arch' not in self.settings:
            dpkg_architecture = DpkgArchitecture()
            self.settings['arch'] = dpkg_architecture.get_deb_host_arch()
            logging.info('No apt target arch set. Using the system arch as fallback: %s' % self.settings['arch'])

    def _load_sources(self):
        if 'sources' not in self.settings:
            raise AptConfigError('Missing sources in apt configuration')

        self._load_source_lines()
        self._load_source_key_urls()

    def _load_source_lines(self):
        if 'sources' not in self.settings:
            raise AptConfigError('Missing sources in the AppDir configuration.')

        if type(self.settings['sources']) is not list:
            raise AptConfigError('Sources list expected instead of: "%s".' % self.settings['sources'])

        for entry in self.settings['sources']:
            if 'sourceline' in entry:
                self._add_source_line(entry['sourceline'])

    def _add_source_line(self, source_line):
        self.apt_source_lines.append(source_line)

    def _load_source_key_urls(self):
        if 'sources' not in self.settings:
            raise AptConfigError('Missing "sources" entry in the AppDir configuration.')

        if type(self.settings['sources']) is not list:
            raise AptConfigError('Sources list expected instead of: "%s".' % self.settings['sources'])

        for entry in self.settings['sources']:
            if 'key_url' in entry:
                self._add_key_url(entry['key_url'])

    def _add_key_url(self, key_url):
        self.apt_source_key_urls.append(key_url)

    def _load_apt_includes(self):
        if 'include' not in self.settings:
            raise AptConfigError('Missing "include" entry in the AppDir configuration.')

        if type(self.settings['include']) is not list:
            raise AptConfigError('include list expected instead of: "%s".' % self.settings['include'])

        self.apt_include = self.settings['include']

    def _load_apt_excludes(self):
        if 'exclude' not in self.settings:
            return

        if type(self.settings['exclude']) is not list:
            raise AptConfigError('exclude list expected instead of: "%s".' % self.settings['exclude'])

        self.apt_exclude = self.settings['exclude']

    def get_apt_conf_path(self):
        return os.path.join(self.apt_prefix, "etc", "apt", "apt.conf")

    def _get_apt_sources_list_path(self):
        return os.path.join(self.apt_prefix, 'etc', 'apt', 'sources.list')

    def _generate_apt_work_dirs(self):
        os.makedirs(self.apt_prefix, exist_ok=True)
        os.makedirs(os.path.join(self.apt_prefix, 'var', 'lib', 'dpkg'), exist_ok=True)
        os.makedirs(self._get_apt_preferences_d_path(), exist_ok=True)
        os.makedirs(self.get_apt_archives_partial_path(), exist_ok=True)

    def _get_dpkg_arch_path(self):
        return os.path.join(self.apt_prefix, 'var', 'lib', 'dpkg', 'arch')

    def _get_apt_keyring_path(self):
        return os.path.join(self.apt_prefix, 'etc', 'apt', 'trusted.gpg')

    def _get_dpkg_status_path(self):
        return os.path.join(self.apt_prefix, 'var', 'lib', 'dpkg', 'status')

    def get_apt_archives_path(self):
        apt_archives_partial_path = os.path.join(self.apt_prefix, 'var', 'cache', 'apt', 'archives')
        return apt_archives_partial_path

    def get_apt_archives_partial_path(self):
        apt_archives_partial_path = os.path.join(self.apt_prefix, 'var', 'cache', 'apt', 'archives', 'partial')
        return apt_archives_partial_path

    def _get_apt_preferences_d_path(self):
        apt_preferences_d_path = os.path.join(self.apt_prefix, 'etc', 'apt', 'preferences.d')
        return apt_preferences_d_path

    def _generate_apt_keyring(self):
        keyring_path = self._get_apt_keyring_path()
        self._make_parent_dirs(keyring_path)

        for key_url in self.apt_source_key_urls:
            self._add_apt_key(key_url, keyring_path)

    def _add_apt_key(self, key_url, keyring_path):
        key = self._get_key_from_cache(key_url)

        if not key:
            key = self._download_key(key_url)
            with open(self._get_apt_key_cache_path(key_url), 'bw') as f:
                f.write(key)

        apt_key = AptKey()
        apt_key.add(key, keyring_path)

    def _get_key_from_cache(self, key_url):
        key_cache_path = self._get_apt_key_cache_path(key_url)

        if os.path.exists(key_cache_path):
            with open(key_cache_path, 'r') as f:
                return f.read().encode()

    def _get_md5(self, key_url):
        m = hashlib.md5()
        m.update(key_url.encode())
        return m.hexdigest()

    def _get_apt_key_cache_path(self, key_url):
        hashed = self._get_md5(key_url)
        return os.path.join(self.apt_prefix, 'etc', 'apt', 'key_%s' % hashed)

    def _download_key(self, key_url):
        logging.info('Importing key: %s' % key_url)
        key = self._try_download_apt_key(key_url)
        return key

    def _try_download_apt_key(self, key_url):
        key = requests.get(key_url)

        if key.status_code != 200:
            raise AptConfigError('Unable to retrieve apt key: %s' % key_url)

        return key.content

    def _generate_apt_conf(self):
        path = self.get_apt_conf_path()
        self._make_parent_dirs(path)

        contents = self._generate_apt_conf_contents()

        with open(path, 'w') as f:
            f.write(contents)

    def _generate_apt_conf_contents(self):
        arch = self.settings['arch']
        return 'apt::Architecture "%s";\n' \
               'APT::Get::Host-Architecture "%s";\n' \
               'Dir "%s";\n' \
               'apt::Get::Download-Only "true";\n' \
               'apt::Install-Recommends "false";\n' \
               'APT::Default-Release "*";' % (arch, arch, self.apt_prefix)

    def _generate_apt_source_list(self):
        path = self._get_apt_sources_list_path()
        self._make_parent_dirs(path)

        contents = self._generate_apt_sources_list_contents()
        with open(path, 'w') as f:
            f.write(contents)

    def _generate_apt_sources_list_contents(self):
        return '\n'.join(self.apt_source_lines)

    def _make_parent_dirs(self, path):
        parent_dir = os.path.dirname(path)
        os.makedirs(parent_dir, exist_ok=True)

    def _generate_dpkg_arch(self):
        path = self._get_dpkg_arch_path()
        self._make_parent_dirs(path)

        with open(path, 'w') as f:
            f.write(self.settings['arch'])

    def _generate_dpkg_status(self):
        path = self._get_dpkg_status_path()
        self._make_parent_dirs(path)

        if not os.path.exists(path):
            os.mknod(path)

    def set_installed_packages(self, pkg_list):
        dpkg_status_path = self._get_dpkg_status_path()

        with open(dpkg_status_path, 'w') as f:
            for pkg in pkg_list:
                status_entry = self._generate_pkg_status_installed_ok_entry(pkg[0], pkg[1])
                f.write(status_entry)

    def clear_installed_packages(self):
        dpkg_status_path = self._get_dpkg_status_path()
        os.unlink(dpkg_status_path)

        self._generate_dpkg_status()

    @staticmethod
    def _generate_pkg_status_installed_ok_entry(pkg_name, pkg_version='9%9z.9.9-1appimage-builder-9'):
        return '\n'.join(['Package: %s' % pkg_name,
                          'Status: install ok installed',
                          'Priority: optional',
                          'Section: libs',
                          'Installed-Size: 0',
                          'Maintainer: Maintainer <maintainer@none.org>',
                          'Architecture: all',
                          'Source: %s' % pkg_name,
                          'Version: %s' % pkg_version,
                          'Depends:',
                          'Description: placeholder package',
                          ' None',
                          'Homepage: http://none.org/',
                          'Original-Maintainer: Maintainer <maintainer@none.org>',
                          '', ''])
