from pathlib import Path
from unittest import TestCase

from appimagebuilder.app_dir.file_info_cache import FileInfoCache
from appimagebuilder.app_dir.runtime.executables import BinaryExecutable, InterpretedExecutable
from appimagebuilder.app_dir.runtime.executables_scanner import ExecutablesScanner


class TestExecutablesScanner(TestCase):
    def setUp(self) -> None:
        self.data_dir = Path(__file__).parent / "data"
        self.file_cache = FileInfoCache(self.data_dir)
        self.file_cache.update()

        self.scanner = ExecutablesScanner(self.data_dir, self.file_cache)

    def test_read_shebang_absolute_path(self):
        file_path = self.data_dir / "script_shebang_abs.py"

        shebang = ExecutablesScanner.read_shebang(file_path)
        self.assertEqual(shebang, ["/usr/bin/python3"])

    def test_read_shebang_relative_path(self):
        file_path = self.data_dir / "script_shebang_rel.py"
        shebang = ExecutablesScanner.read_shebang(file_path)
        self.assertEqual(shebang, ["/usr/bin/env", "python3"])

    def test_read_shebang_no_shebang(self):
        file_path = self.data_dir / "bash"
        shebang = ExecutablesScanner.read_shebang(file_path)
        self.assertIsNone(shebang)

    def test_scan_file_binary_executable(self):
        file_path = self.data_dir / "bash"

        results = self.scanner.scan_file(file_path)
        expected = [BinaryExecutable(file_path, "x86_64")]
        self.assertEqual(expected, results)

    def test_scan_file_interpreted_executable_abs_path(self):
        file_path = self.data_dir / "script_shebang_abs.py"

        results = self.scanner.scan_file(file_path)
        expected = [InterpretedExecutable(file_path, ["/usr/bin/python3"]),
                    BinaryExecutable("/usr/bin/python3", "x86_64")]

        self.assertEqual(expected, results)

    def test_scan_file_interpreted_executable_rel_path(self):
        file_path = self.data_dir / "script_shebang_rel.py"

        results = self.scanner.scan_file(file_path)
        expected = [InterpretedExecutable(file_path, ["/usr/bin/env", "python3"]),
                    BinaryExecutable(str(self.data_dir / "python3"), "x86_64")]

        self.assertEqual(expected, results)
