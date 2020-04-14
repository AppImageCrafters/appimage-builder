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

from .glib_schemas import GLibSchemas


class GLibSchemasTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = GLibSchemas('/AppDir', [
            '/AppDir/usr/share/glib-2.0/schemas/org.gnome.desktop.background.gschema.xml'
        ])

    def test_get_gdk_pixbud_loaders_path(self):
        path = self.helper._get_glib_schemas_path()
        self.assertEqual(path, 'usr/share/glib-2.0/schemas')


if __name__ == '__main__':
    unittest.main()
