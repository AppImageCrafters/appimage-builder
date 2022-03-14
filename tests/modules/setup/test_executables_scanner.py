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
import tempfile
from unittest import TestCase

from appimagebuilder.modules.setup.executables_scanner import ExecutablesScanner


class TestExecutablesScanner(TestCase):
    def test_read_classic_shebang(self):
        with tempfile.NamedTemporaryFile("w+") as shebang_script:
            shebang_script.write("#!/bin/bash")
            shebang_script.flush()

            shebang = ExecutablesScanner.read_shebang(shebang_script.name)
            self.assertEqual(
                shebang,
                [
                    "/bin/bash",
                ],
            )

    def test_read_spaced_classic_shebang(self):
        with tempfile.NamedTemporaryFile("w+") as shebang_script:
            shebang_script.write("#! /bin/bash")
            shebang_script.flush()

            shebang = ExecutablesScanner.read_shebang(shebang_script.name)
            self.assertEqual(
                shebang,
                [
                    "/bin/bash",
                ],
            )

    def test_read_env_shebang(self):
        with tempfile.NamedTemporaryFile("w+") as shebang_script:
            shebang_script.write("#!/usr/bin/env /bin/bash")
            shebang_script.flush()

            shebang = ExecutablesScanner.read_shebang(shebang_script.name)
            self.assertEqual(shebang, ["/usr/bin/env", "/bin/bash"])
