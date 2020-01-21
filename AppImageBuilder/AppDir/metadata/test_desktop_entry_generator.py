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

from .app_info import AppInfo
from .desktop_entry_generator import DesktopEntryGenerator


class DesktopEntryEditorTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.simple_entry = ['[Desktop Entry]\n',
                             'MimeType=application/x-tar\n',
                             'GenericName=Archiving Tool\n',
                             'Name=Ark\n',
                             'Exec=ark %U\n',
                             'Icon=ark\n',
                             'Type=Application\n',
                             'Terminal=false\n',
                             'Categories=Qt;\n',
                             'Comment=Work with file archives\n'
                             ]
        self.editor = DesktopEntryGenerator('/AppDir')

    def test_match_desktop_entry(self):
        self.assertTrue(
            self.editor._match_desktop_entry('org.none.app', '/AppDir/usr/share/applications/org.none.app.desktop'))

    def test_add_appimage_entries(self):
        self.editor.contents = self.simple_entry
        self.editor._add_appimage_name('Ark')
        self.assertTrue('X-AppImage-Name=Ark\n' in self.editor.contents)

    def test_add_appimage_version(self):
        self.editor.contents = self.simple_entry
        self.editor._add_appimage_version('0.1')
        self.assertTrue('X-AppImage-Version=0.1\n' in self.editor.contents)

    def test_add_appimage_arch(self):
        self.editor.contents = self.simple_entry
        self.editor._add_appimage_arch('amd64')
        self.assertTrue('X-AppImage-Arch=amd64\n' in self.editor.contents)

    def test_generate_minimal_desktop_entry(self):
        app_info = AppInfo()
        app_info.id = 'org.none.app'
        app_info.name = 'app'
        app_info.icon = 'app_icon'
        app_info.exec = 'app'
        app_info.exec_args = '$@'

        result = self.editor._generate_minimal_desktop_entry(app_info)
        self.assertEqual(result, [
            '[Desktop Entry]\n',
            'Name=app\n',
            'Exec=app\n',
            'Icon=app_icon\n',
            'Type=Application\n',
            'Terminal=false\n',
            'Categories=Utility;\n',
            'Comment=\n'
        ])


if __name__ == '__main__':
    unittest.main()
