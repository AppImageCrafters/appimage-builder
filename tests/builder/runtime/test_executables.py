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

from pathlib import Path
from unittest import TestCase

from appimagebuilder.modules.setup.executables import (
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
