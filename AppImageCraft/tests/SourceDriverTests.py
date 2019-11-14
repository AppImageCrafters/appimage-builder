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
import tempfile
import unittest

from AppImageCraft import AppDir2
from AppImageCraft.drivers import Source
from AppImageCraft.drivers import SourceDependency


class TestCase(unittest.TestCase):
    def setUp(self):
        self.app_dir_path = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.app_dir_path, "usr", "bin"))
        self.runnable_path = os.path.join(self.app_dir_path, "usr", "bin", "echo")
        shutil.copy("/bin/echo", self.runnable_path)
        self.app_dir = AppDir2(self.app_dir_path)

    def tearDown(self):
        shutil.rmtree(self.app_dir_path)

    def test_list_base_dependencies(self):
        driver = Source()
        dependencies = driver.list_base_dependencies(self.app_dir)
        self.assertEqual([SourceDependency(driver, self.runnable_path, None)], dependencies)


if __name__ == '__main__':
    unittest.main()
