#  Copyright  2022 Alexis Lopez Zubieta
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
import pathlib
import unittest
from shutil import which

from appimagebuilder.modules.deploy.files.dependencies_resolver.elf_resolver import (
    ElfResolver,
)


class ElfResolverTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.bash_path = pathlib.Path(which("bash"))
        self.resolver = ElfResolver()

    def test_resolve_needed_recursively(self):
        results = self.resolver.resolve_needed_recursively(self.bash_path)
        self.assertIn("/lib/x86_64-linux-gnu/libdl.so.2", results)
        self.assertIn("/lib/x86_64-linux-gnu/libc.so.6", results)


if __name__ == "__main__":
    unittest.main()
