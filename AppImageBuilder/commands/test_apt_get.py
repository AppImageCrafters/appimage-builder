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

from AppImageBuilder.commands.apt_get import AptGet
from AppImageBuilder.app_dir.bundlers.apt.config import Config


class AptGetUpdateTestCase(unittest.TestCase):
    def setUp(self):
        self.conf = Config()
        self.temp_prefix_dir = tempfile.TemporaryDirectory()

        self.conf.settings['arch'] = 'amd64'
        self.conf.apt_source_lines = ['deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ bionic main restricted']
        self.conf.apt_source_key_urls = ['http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x3b4fe6acc0b21f32']
        self.conf.apt_prefix = self.temp_prefix_dir.name

        self.conf.generate()

    def tearDown(self):
        self.temp_prefix_dir.cleanup()

    def test_update(self):
        apt_get = AptGet(self.conf.apt_prefix, self.conf.get_apt_conf_path())
        apt_cache_db_path = os.path.join(self.conf.apt_prefix, 'var', 'lib', 'apt', 'lists')
        apt_get.update()
        self.assertTrue(os.listdir(apt_cache_db_path))


class AptGetDownloadTestCase(unittest.TestCase):
    def setUp(self):
        self.conf = Config()
        self.temp_prefix_dir = tempfile.TemporaryDirectory()

        self.conf.settings['arch'] = 'amd64'
        self.conf.apt_source_lines = ['deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ bionic main restricted']
        self.conf.apt_source_key_urls = ['http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x3b4fe6acc0b21f32']
        self.conf.apt_prefix = self.temp_prefix_dir.name

        self.conf.generate()

        self.apt_get = AptGet(self.conf.apt_prefix, self.conf.get_apt_conf_path())
        self.apt_get.update()

    def tearDown(self):
        self.temp_prefix_dir.cleanup()

    def test_download(self):
        package = 'libc6'
        self.apt_get.install([package])

        file_path = self._find_deb_by_package_name(package)
        self.assertTrue(file_path)

    def _find_deb_by_package_name(self, package_name):
        apt_archives_path = os.path.join(self.conf.apt_prefix, 'var', 'cache', 'apt', 'archives')
        apt_archives = os.listdir(apt_archives_path)

        for file_name in apt_archives:
            if file_name.startswith(package_name) and file_name.endswith('.deb'):
                deb_file_path = os.path.join(apt_archives_path, file_name)
                return deb_file_path


if __name__ == '__main__':
    unittest.main()
