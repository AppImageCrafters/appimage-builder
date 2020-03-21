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

from AppImageBuilder.app_dir.runtimes.classic.helpers.fontconfig import FontConfig


class FontConfigCase(unittest.TestCase):
    def setUp(self) -> None:
        self.fc = FontConfig('AppDir', ['AppDir/etc/fonts/fonts.conf'])

    def test_get_font_conf_path(self):
        path = self.fc._get_font_conf_path()
        self.assertEqual(path, 'AppDir/etc/fonts/fonts.conf')

    def test_add_app_dir_relative_fonts_dir_line(self):
        lines = ['<!-- Font directory list -->\n']
        self.fc._add_app_dir_relative_fonts_dir_line(lines)
        self.assertEqual(lines, ['<!-- Font directory list -->\n', '<dir prefix="relative">usr/share/fonts</dir>\n'])


if __name__ == '__main__':
    unittest.main()
