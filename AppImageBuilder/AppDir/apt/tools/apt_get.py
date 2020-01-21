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
import logging
import os
import subprocess


class AptGetError(RuntimeError):
    pass


class AptGet:
    def __init__(self, prefix, config_path):
        self.prefix = prefix
        self.config = config_path

    def install(self, packages):
        errors, output, result = self._call_apt_get_install_download_only(packages)

        if result.returncode != 0:
            for line in errors.splitlines():
                logging.error(line)

            raise AptGetError('Unable to download packages')

        else:
            for line in output.splitlines():
                logging.info(line)

    def _call_apt_get_install_download_only(self, packages):
        command = ["apt-get", "-c", self.config, "--download-only", '-y', '--no-install-recommends', "install"]
        command.extend(packages)
        logging.info(command)

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        errors = result.stderr.decode('utf-8')
        return errors, output, result

    def update(self):
        process, stderr, stdout = self._call_apt_get_update()

        for line in stdout.splitlines():
            logging.info(line)

        if process.wait() != 0:
            raise AptGetError("update failed: %s" % stderr)

    def _call_apt_get_update(self):
        apt_update_command = ["apt-get", "-c", self.config, "update"]
        logging.info(' '.join(apt_update_command))

        process = subprocess.Popen(apt_update_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        stdout, stderr = process.communicate()

        return process, stderr, stdout

    def mark_as_installed(self, default_exclude_list):
        with open(os.path.join(self.prefix, 'var', 'lib', 'dpkg', 'status'), 'w') as f:
            for pkg in default_exclude_list:
                status_entry = self._generate_pkg_status_entry(pkg)
                f.write(status_entry)

    @staticmethod
    def _generate_pkg_status_entry(pkg_name):
        return """Package: %s
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 0
Maintainer: Maintainer <maintainer@none.org>
Architecture: all
Multi-Arch: same
Source: %s
Version: 9999.0.0
Depends: 
Description: None
 None
Homepage: http://none.org/
Original-Maintainer: Maintainer <maintainer@none.org>

""" % (pkg_name, pkg_name)
