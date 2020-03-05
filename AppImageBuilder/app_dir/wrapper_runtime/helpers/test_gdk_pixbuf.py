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

from .gdk_pixbuf import GdkPixbuf


class GdkPixbufTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = GdkPixbuf('/AppDir', [
            '/AppDir/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-svg.so'
        ])

    def test_get_gdk_pixbud_loaders_path(self):
        path = self.helper._get_gdk_pixbud_loaders_path()
        self.assertEqual(path, 'usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders')


if __name__ == '__main__':
    unittest.main()
