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
import tempfile
from pathlib import Path
from unittest import TestCase

from appimagebuilder.modules.setup.executables import (
    BinaryExecutable,
    InterpretedExecutable,
)
from appimagebuilder.modules.setup.executables_scanner import ExecutablesScanner
from appimagebuilder.utils.finder import Finder


class TestExecutablesScanner(TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)

        self.bin_path = self.data_dir / "bin"
        self.bin_path.symlink_to("/bin/bash")

        self.bin_path = self.data_dir / "python3"
        self.bin_path.symlink_to("/usr/bin/python3")

        self.script_abs_shebang_path = self.data_dir / "script_abs_shebang.py"
        with self.script_abs_shebang_path.open("w") as f:
            f.write("#!/usr/bin/python3\n" "print 'hello world'\n")

        self.script_rel_shebang_path = self.data_dir / "script_rel_shebang.py"
        with self.script_rel_shebang_path.open("w") as f:
            f.write("#!/usr/bin/env python3\n" "print 'hello world'\n")

        self.file_cache = Finder(self.data_dir)

        self.scanner = ExecutablesScanner(self.data_dir, self.file_cache)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_read_shebang_absolute_path(self):
        shebang = ExecutablesScanner.read_shebang(self.script_abs_shebang_path)
        self.assertEqual(shebang, ["/usr/bin/python3"])

    def test_read_shebang_relative_path(self):
        shebang = ExecutablesScanner.read_shebang(self.script_rel_shebang_path)
        self.assertEqual(shebang, ["/usr/bin/env", "python3"])

    def test_read_shebang_no_shebang(self):
        shebang = ExecutablesScanner.read_shebang(self.bin_path)
        self.assertIsNone(shebang)

    def test_scan_file_binary_executable(self):
        results = self.scanner.scan_file(self.bin_path)
        expected = [BinaryExecutable(self.bin_path, "x86_64")]
        self.assertEqual(expected, results)

    def test_scan_file_interpreted_executable_abs_path(self):
        results = self.scanner.scan_file(self.script_abs_shebang_path)
        python3_bin_path = pathlib.Path("/usr/bin/python3").resolve()
        python_binary = BinaryExecutable(str(python3_bin_path), "x86_64")
        script = InterpretedExecutable(
            self.script_abs_shebang_path, ["/usr/bin/python3"]
        )
        script.interpreter = python_binary

        self.assertEqual([script, python_binary], results)

    def test_scan_file_interpreted_executable_rel_path(self):
        results = self.scanner.scan_file(self.script_rel_shebang_path)
        python3_bin_path = pathlib.Path("/usr/bin/python3").resolve()
        python_binary = BinaryExecutable(str(python3_bin_path), "x86_64")
        script = InterpretedExecutable(
            self.script_rel_shebang_path, ["/usr/bin/env", "python3"]
        )
        script.interpreter = python_binary

        self.assertEqual([script, python_binary], results)
