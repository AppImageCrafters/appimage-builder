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
import urllib.request

from .dpkg_deb import DpkgDeb


class DpkgDebTestCase(unittest.TestCase):
    def setUp(self):
        url = 'http://archive.ubuntu.com/ubuntu/pool/main/g/gcc-8/gcc-8-multilib_8.2.0-7ubuntu1_amd64.deb'
        response = urllib.request.urlopen(url)

        self.assertTrue(response.code, 200)

        self.temp_prefix_dir = tempfile.TemporaryDirectory()
        self.deb_file_path = os.path.join(self.temp_prefix_dir.name, 'gcc-8-multilib_8.2.0-7ubuntu1_amd64.deb')

        with open(self.deb_file_path, 'wb') as f:
            data = response.read()
            f.write(data)

    def tearDown(self):
        self.temp_prefix_dir.cleanup()

    def test_extract(self):
        dpkg_deb = DpkgDeb()
        dpkg_deb.extract(self.deb_file_path, self.temp_prefix_dir.name)

        extracted_file_path = os.path.join(self.temp_prefix_dir.name, "usr")
        self.assertTrue(os.path.exists(extracted_file_path))


if __name__ == '__main__':
    unittest.main()
