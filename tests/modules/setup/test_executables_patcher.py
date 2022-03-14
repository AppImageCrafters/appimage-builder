import os
import pathlib
import tempfile
import unittest

from appimagebuilder.modules.setup.executables_patcher import ExecutablesPatcher


class TestExecutablesPatcher(unittest.TestCase):
    def test_read_interpreter_path_from_shebang(self):
        r = ExecutablesPatcher.read_interpreter_path_from_shebang("#!/bin/bash")
        self.assertEqual("/bin/bash", r)

        r = ExecutablesPatcher.read_interpreter_path_from_shebang("#! bin/bash")
        self.assertEqual("bin/bash", r)

        r = ExecutablesPatcher.read_interpreter_path_from_shebang("#!  bin/env bash")
        self.assertEqual("bin/env", r)

    def test_make_bin_path_in_shebang_relative(self):
        orig = "#!/bin/env python3\n"
        patched = ExecutablesPatcher.make_bin_path_in_shebang_relative(orig)

        self.assertEqual(len(orig), len(patched))
        self.assertEqual("#! bin/env python3\n", patched)

    def test_make_bin_path_in_shebang_relative_with_space(self):
        orig = "#! /bin/env python3\n"
        patched = ExecutablesPatcher.make_bin_path_in_shebang_relative(orig)

        self.assertEqual(len(orig), len(patched))
        self.assertEqual("#!  bin/env python3\n", patched)

    def test_patch_interpreted_executable(self):
        patcher = ExecutablesPatcher()

        with tempfile.NamedTemporaryFile("w+") as file_mock:
            file_mock.write("#!/bin/bash\n")
            file_mock.flush()
            os.fsync(file_mock)

            file_mock_path = pathlib.Path(file_mock.name)
            patcher.patch_interpreted_executable(file_mock_path)

            file_mock.seek(0)
            patched_shebang = file_mock.readline()

            expected_shebang = "#! bin/bash\n"
            self.assertEqual(expected_shebang, patched_shebang)
            self.assertEqual(
                "bin/bash", patcher.used_interpreters_paths[file_mock_path]
            )


if __name__ == "__main__":
    unittest.main()
