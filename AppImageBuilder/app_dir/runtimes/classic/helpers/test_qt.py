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
from .qt import Qt


class QtHelperTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.app_dir_files = [
            '/AppDir/usr/lib/x86_64-linux-gnu/libQt5Core.so.5',
            '/AppDir/usr/lib/x86_64-linux-gnu/qt5/libexec/QtWebProcess',
            '/AppDir/usr/lib/x86_64-linux-gnu/qt5/plugins/platforms/libqxcb.so',
            '/AppDir/usr/lib/x86_64-linux-gnu/qt5/qml/org/kde/plasma/components/Label.qml',
            '/AppDir/usr/share/qt5/translations/qtbase_en.qm'
        ]
        self.app_dir = '/AppDir'
        self.qt = Qt(self.app_dir, self.app_dir_files)

    def test_get_qt_(self):
        self.assertEqual(self.qt._get_qt_conf_prefix_path('/AppDir/lib/x86_64'), '../..')

    def test_get_qt_libs_path(self):
        self.assertEqual(self.qt._get_qt_libs_path(), 'usr/lib/x86_64-linux-gnu')

    def test_get_qt_lib_exec_path(self):
        self.assertEqual(self.qt._get_qt_lib_exec_path(), 'usr/lib/x86_64-linux-gnu/qt5/libexec')

    def test_get_qt_plugins_path(self):
        self.assertEqual(self.qt._get_qt_plugins_path(), 'usr/lib/x86_64-linux-gnu/qt5/plugins')

    def test_get_qt_qml_path(self):
        self.assertEqual(self.qt._get_qt_qml_path(), 'usr/lib/x86_64-linux-gnu/qt5/qml')

    def test_get_qt_translations_path(self):
        self.assertEqual(self.qt._get_qt_translations_path(), 'usr/share/qt5/translations')

    def test_get_qt_data_dir(self):
        self.assertEqual(self.qt._get_qt_data_dir(), 'usr/share/qt5')


if __name__ == '__main__':
    unittest.main()
