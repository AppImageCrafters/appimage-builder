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

import unittest

from AppImageBuilder.tools.LinkerTool import LinkerTool


class LinkerToolTestCase(unittest.TestCase):

    def __init__(self, methodName: str = ...) -> None:
        super().__init__(methodName)
        self.ldd_tool = LinkerTool()

    def test_list_dependencies(self):
        dependencies_map = self.ldd_tool.list_link_dependencies("/bin/echo")
        assert dependencies_map

    def test_parse_output_regular(self):
        output = self.ldd_tool._parse(
            "        linux-vdso.so.1 (0x00007f4fc901c000)\n"
            "        libc.so.6 => /AppDir/lib/x86_64-linux-gnu/libc.so.6 (0x00007f4fc8803000)\n"
            "        /AppDir/lib/x86_64-linux-gnu/ld-2.27.so (0x00007f4fc8df7000)\n")

        expected = {
            "linux-vdso.so.1": None,
            "libc.so.6": "/AppDir/lib/x86_64-linux-gnu/libc.so.6",
            "/AppDir/lib/x86_64-linux-gnu/ld-2.27.so": None
        }

        assert output == expected

    def test_parse_output_static(self):
        output = self.ldd_tool._parse("        statically linked\n")
        expected = {}
        assert output == expected


if __name__ == '__main__':
    unittest.main()
