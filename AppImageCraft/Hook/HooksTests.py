#  Copyright  2019 Alexis Lopez Zubieta
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

import os
import shutil
import unittest
import tempfile
import configparser
from AppImageCraft.AppDir import AppDir
from AppImageCraft.Hook.Qt5Hook import Qt5Hook

class Qt5HookTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.app_dir = AppDir(path=self.temp_dir)
        self.app_dir.install()
        self.app_dir.libs_registry["libQt5Core.so.5"] = "/fake/path"

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_inactive_hook(self):
        del self.app_dir.libs_registry["libQt5Core.so.5"]

        qt5_hook = Qt5Hook(self.app_dir)
        assert not qt5_hook.active()

    def test_active_hook(self):
        qt5_hook = Qt5Hook(self.app_dir)
        assert qt5_hook.active()

    def test_generate_qt_conf(self):
        qt5_hook = Qt5Hook(self.app_dir)
        qt5_hook.after_install()

        qt_conf_path = os.path.join(self.app_dir.path, "lib", "x86_64-linux-gnu", "qt.conf")
        assert os.path.exists(qt_conf_path)

        qt_conf = configparser.ConfigParser()
        qt_conf.read(qt_conf_path)

        assert qt_conf['Paths']["Prefix"] == "../../usr"
        assert qt_conf['Paths']["Settings"] == "../../etc"

if __name__ == '__main__':
    unittest.main()
