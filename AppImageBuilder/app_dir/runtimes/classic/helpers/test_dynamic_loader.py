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

from AppImageBuilder.app_dir.runtimes.classic import DynamicLoader


class DynamicLoaderTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.app_dir_files = [
            'AppDir/lib/',
            'AppDir/lib/ld-linux-aarch64.so.1',
            'AppDir/lib/aarch64-linux-gnu',
            'AppDir/lib/aarch64-linux-gnu/libpthread-2.27.so',
            'AppDir/lib/aarch64-linux-gnu/libnss_hesiod-2.27.so',
            'AppDir/lib/aarch64-linux-gnu/libnss_nis.so.2',
            'AppDir/lib/aarch64-linux-gnu/libmemusage.so',
            'AppDir/lib/aarch64-linux-gnu/ld-2.27.so',
            'AppDir/lib/aarch64-linux-gnu/libpthread.so.0',
            'AppDir/lib/aarch64-linux-gnu/libacl.so.1.1.0',
            'AppDir/lib/aarch64-linux-gnu/libcrypt.so.1',
            'AppDir/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1',
            'AppDir/lib/aarch64-linux-gnu/libutil.so.1',
            'AppDir/lib/aarch64-linux-gnu/libnsl.so.1',
        ]

    def test_get_binary_path(self):
        dl = DynamicLoader('AppDir', self.app_dir_files)
        self.assertEqual(dl.get_binary_path(), 'lib/aarch64-linux-gnu/ld-2.27.so')

    def test_list_libs(self):
        dl = DynamicLoader('AppDir', ['/path/to/file', 'path/to/shared_lib.so', 'path/to/shared_lib.so.1'])
        self.assertEqual(dl._list_libs(), ['path/to/shared_lib.so', 'path/to/shared_lib.so.1'])