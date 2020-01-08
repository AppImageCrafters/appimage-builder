#  Copyright  2019 Alexis Lopez Zubieta
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


import logging
import os
import subprocess

import requests


class AptTool:
    arch = None
    sources = []

    def __init__(self) -> None:
        super().__init__()
        self.logger = logging.getLogger('apt')

    def update(self):
        apt_update_command = ["apt-get", "-c", self.config_file_path, "update"]
        self.logger.info(' '.join(apt_update_command))
        process = subprocess.Popen(apt_update_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        for line in stdout.splitlines():
            self.logger.info(line)

        if process.wait() != 0:
            self.logger.error("apt-get update failed: %s" % stderr)

    def configure(self, arch, root, sources):
        self.root = root
        self.arch = arch
        self.sources = sources
        self.config_file_path = os.path.join(root, "etc", "apt", "apt.conf")
        self.keyring_file_path = os.path.join(root, "etc", "apt", "trusted.gpg")

        os.makedirs(os.path.join(self.root, 'var', 'lib', 'dpkg'), exist_ok=True)
        os.makedirs(os.path.join(self.root, 'etc', 'apt', 'preferences.d'), exist_ok=True)
        os.makedirs(os.path.join(self.root, 'var', 'cache', 'apt', 'archives', 'partial'), exist_ok=True)
        with open(os.path.join(self.root, 'var/lib/dpkg/arch'), 'w') as f:
            f.write(self.arch)

        if not os.path.exists(os.path.join(self.root, 'var', 'lib', 'dpkg', 'status')):
            os.mknod(os.path.join(self.root, 'var', 'lib', 'dpkg', 'status'))

        self._write_apt_conf()
        self._add_sources()

    def _add_sources(self):
        os.makedirs(os.path.dirname(self.keyring_file_path), exist_ok=True)
        sources_list_path = os.path.join(self.root, 'etc', 'apt', 'sources.list')
        sources_list = open(sources_list_path, "w")

        for source in self.sources:
            if 'key_url' in source:
                key_url = source['key_url']
                key = requests.get(key_url)
                if key.status_code == 200:
                    apt_key_command = ["fakeroot", "apt-key", "--keyring", self.keyring_file_path, "add", "-"]
                    self.logger.info("Adding apt key: %s" % key_url)

                    self.logger.info(' '.join(apt_key_command))
                    process = subprocess.Popen(apt_key_command, cwd=self.root, stdin=subprocess.PIPE,
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate(key.content)
                    if process.wait() != 0:
                        errors = stderr.decode('utf-8')
                        self.logger.warning("Unable to add key: %s. %s" % (key_url, errors))
                    else:
                        self.logger.info(stdout.decode('utf-8'))

                else:
                    self.logger.warning("Unable to retrieve key: %s" % key_url)

            if 'sourceline' in source:
                sources_list.write('%s\n' % source['sourceline'])

        sources_list.close()

    def _write_apt_conf(self):
        os.makedirs(os.path.dirname(self.config_file_path), exist_ok=True)

        with open(self.config_file_path, "w") as f:
            f.write('Apt::Architecture "%s";\n' % self.arch)
            f.write('APT::Get::Host-Architecture "%s";\n' % self.arch)

            f.write('Dir "%s";\n' % self.root)
            f.write('Apt::Get::Download-Only "true";\n')
            f.write('Apt::Install-Recommends "false";\n')
            f.write('APT::Default-Release "*";\n')

    @staticmethod
    def get_host_sources():
        return []

    def dependencies(self, packages):
        command = ["apt-cache", "-c", self.config_file_path, "depends", "--recurse", "--no-recommends", "--no-suggests",
                   "--no-conflicts", "--no-breaks", "--no-replaces", "--no-enhances", "--no-pre-depends"]
        command.extend(packages)

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        errors = result.stderr.decode('utf-8')

        depends = []
        if result.returncode != 0:
            self.logger.warning("Unable to find %s dependencies: %s" % (packages, errors))
        else:
            for line in output.splitlines():
                # package names starts a the beginning of the line
                if line.startswith(' '):
                    continue

                package, arch = line.split(':', 1) if ':' in line else (line, self.arch)
                if self.arch in arch or 'any' in arch:
                    depends.append(line)

        return depends

    def download(self, packages):
        # exclude virtual packages
        packages = [package for package in packages if not package.startswith('<')]

        command = ["apt-get", "-c", self.config_file_path, "download"]
        command.extend(packages)

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=os.path.join(self.root, 'var', 'cache', 'apt', 'archives'))
        output = result.stdout.decode('utf-8')
        errors = result.stderr.decode('utf-8')

        depends = []
        if result.returncode != 0:
            self.logger.error("Unable to download packages")
            for line in errors.splitlines():
                self.logger.error(line)
        else:
            for line in output.splitlines():
                self.logger.info(line)

        return depends
