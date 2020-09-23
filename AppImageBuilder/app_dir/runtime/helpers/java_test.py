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

import unittest

from .java import Java


class JavaTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.app_dir_files = [
            'AppDir/lib/',
            'AppDir/usr/lib/jvm/java-1.11.0-openjdk-i386/bin/java',
        ]

    def test_get_java_home_dir(self):
        java = Java('AppDir', self.app_dir_files)
        self.assertEqual(java._get_java_home_dir(), 'usr/lib/jvm/java-1.11.0-openjdk-i386')


if __name__ == '__main__':
    unittest.main()
