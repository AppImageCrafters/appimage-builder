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
