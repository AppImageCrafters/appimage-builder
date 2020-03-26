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
        self.helper = GdkPixbuf('/AppDir/', [
            '/AppDir/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-svg.so'
        ])

    def test_get_gdk_pixbud_loaders_path(self):
        path = self.helper._get_gdk_pixbuf_loaders_path()
        self.assertEqual(path, 'usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders')

    def test_remove_loaders_path_prefixes(self):
        input = '''# GdkPixbuf Image Loader Modules file
# Automatically generated file, do not edit
# Created by gdk-pixbuf-query-loaders from gdk-pixbuf-2.36.11
#
# LoaderDir = /usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders
#
"/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-ani.so"
"ani" 4 "gdk-pixbuf" "Windows animated cursor" "LGPL"
"application/x-navi-animation" ""
"ani" ""
"RIFF    ACON" "    xxxx    " 100

"/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-bmp.so"
"bmp" 5 "gdk-pixbuf" "BMP" "LGPL"
"image/bmp" "image/x-bmp" "image/x-MS-bmp" ""
"bmp" ""
"BM" "" 100

'''
        expected = '''# GdkPixbuf Image Loader Modules file
# Automatically generated file, do not edit
# Created by gdk-pixbuf-query-loaders from gdk-pixbuf-2.36.11
#
# LoaderDir = /usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders
#
"libpixbufloader-ani.so"
"ani" 4 "gdk-pixbuf" "Windows animated cursor" "LGPL"
"application/x-navi-animation" ""
"ani" ""
"RIFF    ACON" "    xxxx    " 100

"libpixbufloader-bmp.so"
"bmp" 5 "gdk-pixbuf" "BMP" "LGPL"
"image/bmp" "image/x-bmp" "image/x-MS-bmp" ""
"bmp" ""
"BM" "" 100

'''
        output = self.helper._remove_loaders_path_prefixes(input.splitlines())
        self.assertEqual(output, expected.splitlines())


if __name__ == '__main__':
    unittest.main()
