from pathlib import Path
from unittest import TestCase

from appimagebuilder.app_dir.runtime.executables import (
    InterpretedExecutable,
)


class TestInterpretedExecutable(TestCase):
    def setUp(self) -> None:
        self.data_dir = Path(__file__).parent / "data"

    def test_read_shebang_absolute_path(self):
        file_path = self.data_dir / "script_shebang_abs.py"

        expected = InterpretedExecutable(file_path, ["/usr/bin/python3"])

        self.assertEqual(expected.path, file_path)
        self.assertEqual(expected.shebang, ["/usr/bin/python3"])

    def test_read_shebang_relative_path(self):
        file_path = self.data_dir / "script_shebang_rel.py"
        expected = InterpretedExecutable(file_path, ["/usr/bin/env", "python3"])
        self.assertEqual(expected.path, file_path)
        self.assertEqual(expected.shebang, ["/usr/bin/env", "python3"])
