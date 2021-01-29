#  Copyright  2021 Alexis Lopez Zubieta
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

#  Copyright  2021 Alexis Lopez Zubieta
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
from unittest import TestCase

from appimagebuilder.common.finder import Finder


class TestFinder(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.finder = Finder("/usr/")

    def test_find_executable_file_symlink(self):
        results = self.finder.find(
            "python3", [Finder.is_file, Finder.is_executable, Finder.is_symlink]
        )
        self.assertIn(pathlib.Path("/usr/bin/python3"), results)
        self.assertNotIn(pathlib.Path("/usr/share/python3"), results)

    def test_find_file_elf(self):
        results = self.finder.find(
            "python3", [Finder.is_file, Finder.is_dynamically_linked_executable]
        )
        self.assertIn(pathlib.Path("/usr/bin/python3"), results)
        self.assertNotIn(pathlib.Path("/usr/share/python3"), results)

    def test_find_file_not_elf(self):
        results = self.finder.find("bin/*", [], [Finder.is_elf])
        self.assertNotIn(pathlib.Path("/usr/bin/python3"), results)

    def test_find_dir(self):
        finder = Finder("/usr/")
        results = finder.find("python3", [Finder.is_dir])
        self.assertIn(pathlib.Path("/usr/share/python3"), results)
        self.assertNotIn(pathlib.Path("/usr/bin/python3"), results)

    def test_find_dynamically_linked_executable(self):
        results = self.finder.find(
            "python3", [Finder.is_file, Finder.is_dynamically_linked_executable]
        )
        self.assertIn(pathlib.Path("/usr/bin/python3"), results)
        self.assertNotIn(pathlib.Path("/usr/share/python3"), results)

    def test_find_elf_lib_and_executable(self):
        finder = Finder("/lib")
        results = finder.find(
            "libc.*",
            [Finder.is_dynamically_linked_executable, Finder.is_elf_shared_lib],
        )
        self.assertIn(pathlib.Path("/lib/x86_64-linux-gnu/libc.so.6"), results)

    def test_match_patterns(self):
        self.assertTrue(
            self.finder.match_patterns(
                pathlib.Path("AppDir/opt/libc/lib/x86_64-linux-gnu"), ["*/opt/libc/*"]
            )
        )

    def test_find_dirs_containing(self):
        finder = Finder("/lib")
        results = finder.find_dirs_containing(
            pattern="*.so*",
            file_checks=[Finder.is_file, Finder.is_elf, Finder.is_elf_shared_lib],
            excluded_patterns=[
                "*/device-mapper",
            ],
        )
        results = list(results)
        self.assertIn(pathlib.Path("/lib/x86_64-linux-gnu"), results)
        self.assertNotIn(pathlib.Path("/lib/apparmor"), results)
        self.assertNotIn(pathlib.Path("/lib/x86_64-linux-gnu/device-mapper"), results)

    def test_find_dirs_containing_excluding(self):
        finder = Finder("/lib")
        results = finder.find_dirs_containing(
            pattern="*.so*",
            file_checks=[Finder.is_file, Finder.is_elf, Finder.is_elf_shared_lib],
            excluded_patterns=[
                "*/x86_64-linux-gnu",
            ],
        )
        results = list(results)
        self.assertNotIn(pathlib.Path("/lib/x86_64-linux-gnu"), results)
