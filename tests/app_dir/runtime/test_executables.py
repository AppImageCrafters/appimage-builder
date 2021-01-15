from pathlib import Path
from unittest import TestCase

from appimagebuilder.app_dir.file_info_cache import FileInfoCache
from appimagebuilder.app_dir.runtime.executables import InterpretedExecutable, ExecutableProcessingError, \
    search_interpreted_executables


class TestInterpretedExecutable(TestCase):
    def setUp(self) -> None:
        self.data_dir = Path(__file__).parent / "data"

    def test_read_shebang_absolute_path(self):
        file_path = self.data_dir / "script_shebang_abs.py"

        module = InterpretedExecutable(file_path)

        self.assertEqual(module.path, file_path)
        self.assertEqual(module.shebang, ["/usr/bin/python3"])

    def test_read_shebang_relative_path(self):
        file_path = self.data_dir / "script_shebang_rel.py"
        module = InterpretedExecutable(file_path)
        self.assertEqual(module.path, file_path)
        self.assertEqual(module.shebang, ["/usr/bin/env", "python3"])

    def test_read_shebang_no_shebang(self):
        file_path = self.data_dir / "bash"
        self.assertRaises(ExecutableProcessingError, InterpretedExecutable, file_path)

    def test_search_interpreted_executables(self):
        file_cache = FileInfoCache(self.data_dir)
        file_cache.update()

        expected = [
            InterpretedExecutable(str(self.data_dir / "script_shebang_rel.py")),
            InterpretedExecutable(str(self.data_dir / "script_shebang_abs.sh")),
            InterpretedExecutable(str(self.data_dir / "script_shebang_abs.py")),
        ]

        results = search_interpreted_executables(file_cache)
        self.assertEqual(expected, results)
