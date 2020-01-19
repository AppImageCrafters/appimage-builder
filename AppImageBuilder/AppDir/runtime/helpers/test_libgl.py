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

from .libgl import LibGL


class LibGLTestCase(unittest.TestCase):
    def test_get_dri_path(self):
        libgl = LibGL('AppDir', ['AppDir/usr/lib/x86_64-linux-gnu/dri/i965_dri.so'])
        self.assertEqual(libgl._get_dri_path(), 'usr/lib/x86_64-linux-gnu/dri')


if __name__ == '__main__':
    unittest.main()
