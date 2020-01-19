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

from .openssl import OpenSSL


class OpenSSLTestCase(unittest.TestCase):
    def test_get_engines_dir(self):
        open_ssl = OpenSSL('AppDir', ['AppDir/usr/lib/x86_64-linux-gnu/openssl-1.0.0/engines/libaep.so'])
        self.assertEqual(open_ssl._get_engines_dir(), 'usr/lib/x86_64-linux-gnu/openssl-1.0.0/engines')


if __name__ == '__main__':
    unittest.main()
