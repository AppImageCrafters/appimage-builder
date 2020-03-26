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
import os
import tempfile
import unittest

from AppImageBuilder.app_dir.bundlers.apt.config import Config, AptConfigError


class LoadAptConfigTestCase(unittest.TestCase):
    def setUp(self):
        self.conf = Config('/tmp')

    def test_load_arch(self):
        self.conf.settings = {'arch': 'arm64'}
        self.conf._load_arch()

        self.assertEqual(self.conf.settings['arch'], 'arm64')

    def test_load_arch_fallback(self):
        self.conf.settings = {}
        self.conf._load_arch()

        self.assertTrue(self.conf.settings['arch'])

    def test_load_missing_sources(self):
        self.conf.settings = {}
        self.assertRaises(AptConfigError, self.conf._load_source_lines)

    def test_load_broken_sources(self):
        self.conf.settings = {'sources': {'test': 'test'}}
        self.assertRaises(AptConfigError, self.conf._load_source_lines)

    def test_load_sources(self):
        self.conf.settings = \
            {'sources': [
                {
                    'sourceline': 'deb [arch=amd64] http://mx.archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse'
                },
                {
                    'sourceline': 'deb [arch=amd64] http://mx.archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse'
                }
            ]}

        self.conf._load_source_lines()

        self.assertEqual(self.conf.apt_source_lines, [
            'deb [arch=amd64] http://mx.archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse',
            'deb [arch=amd64] http://mx.archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse'
        ])

    def test_load_key_urls(self):
        self.conf.settings = \
            {'sources': [{'key_url': 'http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x3b4fe6acc0b21f32'}]}

        self.conf._load_source_key_urls()

        self.assertEqual(self.conf.apt_source_key_urls,
                         ['http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x3b4fe6acc0b21f32'])

    def test_load_apt_missing_includes(self):
        self.conf.settings = {}
        self.assertRaises(AptConfigError, self.conf._load_apt_includes)

    def test_load_broken_apt_includes(self):
        self.conf.settings = {'include': {'qmlscene': 'as'}}
        self.assertRaises(AptConfigError, self.conf._load_apt_includes)

    def test_load_apt_includes(self):
        self.conf.settings = {'include': ['qmlscene']}

        self.conf._load_apt_includes()
        self.assertEqual(self.conf.apt_include, ['qmlscene'])

    def test_load_missing_apt_excludes(self):
        self.conf.settings = {}

        self.conf._load_apt_excludes()
        self.assertFalse(self.conf.apt_exclude)

    def test_load_broken_apt_excludes(self):
        self.conf.settings = {'exclude': {'qmlscene': 'as'}}
        self.assertRaises(AptConfigError, self.conf._load_apt_excludes)

    def test_load_apt_excludes(self):
        self.conf.settings = {'exclude': ['qmlscene']}
        self.conf._load_apt_excludes()
        self.assertEqual(self.conf.apt_exclude, ['qmlscene'])


class GenerateAptConfigTestCase(unittest.TestCase):
    def setUp(self):
        self.conf = Config()
        self.temp_prefix_dir = tempfile.TemporaryDirectory()
        self.temp_prefix_dir_path = self.temp_prefix_dir.name

        self.apt_arch = 'amd64'
        self.conf.settings['arch'] = self.apt_arch
        self.conf.apt_prefix = self.temp_prefix_dir.name

    def tearDown(self):
        self.temp_prefix_dir.cleanup()

    def test_generate_apt_source(self):
        self.conf.apt_source_lines = [
            'deb [arch=amd64] http://mx.archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse',
            'deb [arch=amd64] http://mx.archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse'
        ]

        apt_source_list = self.conf._generate_apt_sources_list_contents()
        self.assertEqual(apt_source_list,
                         'deb [arch=amd64] http://mx.archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse\n'
                         'deb [arch=amd64] http://mx.archive.ubuntu.com/ubuntu/ bionic-updates main restricted universe multiverse'
                         )

    def test_generate_apt_conf(self):
        apt_conf = self.conf._generate_apt_conf_contents()
        self.assertEqual(apt_conf,
                         'apt::Architecture "%s";\n'
                         'APT::Get::Host-Architecture "%s";\n'
                         'Dir "%s";\n'
                         'apt::Get::Download-Only "true";\n'
                         'apt::Install-Recommends "false";\n'
                         'APT::Default-Release "*";' % (self.apt_arch, self.apt_arch, self.temp_prefix_dir_path)
                         )

    def test_get_apt_conf_path(self):
        apt_conf_path = self.conf.get_apt_conf_path()
        self.assertEqual(apt_conf_path, os.path.join(self.temp_prefix_dir_path, 'etc', 'apt', 'apt.conf'))

    def test_get_apt_source_list_path(self):
        apt_source_list_path = self.conf._get_apt_sources_list_path()
        self.assertEqual(apt_source_list_path, os.path.join(self.temp_prefix_dir_path, 'etc', 'apt', 'sources.list'))

    def test_generate_apt_dirs(self):
        self.conf._generate_apt_work_dirs()

        self.assertTrue(os.path.isdir(os.path.join(self.temp_prefix_dir_path, 'var', 'lib', 'dpkg')))
        self.assertTrue(os.path.isdir(os.path.join(self.temp_prefix_dir_path, 'etc', 'apt', 'preferences.d')))
        self.assertTrue(os.path.isdir(os.path.join(self.temp_prefix_dir_path,
                                                   'var', 'cache', 'apt', 'archives', 'partial')))

    def test_get_dpkg_arch_path(self):
        dpkg_arch_path = self.conf._get_dpkg_arch_path()
        self.assertEqual(dpkg_arch_path, os.path.join(self.temp_prefix_dir_path, 'var', 'lib', 'dpkg', 'arch'))

    def test_get_dpkg_status_path(self):
        dpkg_status_path = self.conf._get_dpkg_status_path()
        self.assertEqual(dpkg_status_path, os.path.join(self.temp_prefix_dir_path, 'var', 'lib', 'dpkg', 'status'))

    def test_get_apt_keyring_path(self):
        apt_keyring_path = self.conf._get_apt_keyring_path()
        self.assertEqual(apt_keyring_path, os.path.join(self.temp_prefix_dir_path, 'etc', 'apt', 'trusted.gpg'))

    def test_generate_apt_keyring(self):
        self.conf.apt_source_key_urls = ['http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x3b4fe6acc0b21f32']

        self.conf._generate_apt_keyring()

        self.assertTrue(os.path.exists(self.conf._get_apt_keyring_path()))

    def test_generate_config(self):
        self.apt_arch = 'amd64'
        self.conf.apt_source_lines = ['deb http://archive.ubuntu.com/ubuntu/ bionic main restricted']
        self.conf.apt_source_key_urls = ['http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x3b4fe6acc0b21f32']

        self.conf.generate()

        self.assertTrue(os.path.exists(self.conf.get_apt_conf_path()))
        self.assertTrue(os.path.exists(self.conf._get_apt_keyring_path()))
        self.assertTrue(os.path.exists(self.conf._get_apt_sources_list_path()))
        self.assertTrue(os.path.exists(self.conf._get_dpkg_arch_path()))
        self.assertTrue(os.path.exists(self.conf._get_dpkg_status_path()))

    def test_generate_pkg_status_installed_ok_entry(self):
        result = self.conf._generate_pkg_status_installed_ok_entry('package')
        self.assertEqual(result,
                         '\n'.join(['Package: %s' % 'package',
                                    'Status: install ok installed',
                                    'Priority: optional',
                                    'Section: libs',
                                    'Installed-Size: 0',
                                    'Maintainer: Maintainer <maintainer@none.org>',
                                    'Architecture: all',
                                    'Multi-Arch: same',
                                    'Source: %s' % 'package',
                                    'Version: 9999.0.0',
                                    'Depends:',
                                    'Description: None',
                                    ' None',
                                    'Homepage: http://none.org/',
                                    'Original-Maintainer: Maintainer <maintainer@none.org>',
                                    '', '']))


if __name__ == '__main__':
    unittest.main()
