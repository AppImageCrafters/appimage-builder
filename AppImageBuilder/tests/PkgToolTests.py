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

from AppImageBuilder.tools.PkgTool import PkgTool


class PkgToolTestCase(unittest.TestCase):

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.pkg_tool = PkgTool()

    def test_find_pkgs_of(self):
        pkgs = self.pkg_tool.find_owner_packages("/bin/echo")
        self.assertEqual(pkgs, {"coreutils"})

    def test_deploy_pkgs(self):
        temp_dir = tempfile.mkdtemp()

        self.pkg_tool.deploy_pkgs(['less'], temp_dir)

        deployed_files = []
        for root, dirs, files in os.walk(temp_dir):
            for filename in files:
                deployed_files.append(os.path.join(root, filename))

        print(deployed_files)
        shutil.rmtree(temp_dir)

        assert deployed_files

if __name__ == '__main__':
    unittest.main()
