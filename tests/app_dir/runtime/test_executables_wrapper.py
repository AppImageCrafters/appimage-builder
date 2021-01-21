import filecmp
import os
from pathlib import Path
from unittest import TestCase

from appimagebuilder.app_dir.runtime.executables import Executable
from appimagebuilder.app_dir.runtime.executables_wrapper import ExecutablesWrapper


class TestExecutablesWrapper(TestCase):
    def setUp(self) -> None:
        self.data_dir = Path(__file__).parent / "data"
        self.apprun_path = self.data_dir / "python3"
        self.bin_path = self.data_dir / "bash"
        self.env_path = self.data_dir / "bash.env"
        self.wrapped_path = self.data_dir / "bash.orig"

    def tearDown(self) -> None:
        if self.wrapped_path.exists():
            if self.bin_path.exists():
                os.remove(self.bin_path)

            self.wrapped_path.rename(self.bin_path)

        if self.env_path.exists():
            os.remove(self.env_path)

    def test_wrap(self):
        wrapper = ExecutablesWrapper(self.apprun_path, self.data_dir, {})
        wrapper.wrap(Executable(self.bin_path), {})

        self.assertTrue(self.wrapped_path.exists())

        self.assertTrue(self.env_path.exists())

        self.assertTrue(filecmp.cmp(self.bin_path, self.apprun_path))

    def test_generate_executable_env(self):
        executable = Executable(self.bin_path)
        wrapper = ExecutablesWrapper(
            self.apprun_path, self.data_dir, {"APPDIR_LIBRARY_PATH": "$APPDIR/usr/lib"}
        )
        result = wrapper._generate_executable_env(
            executable, self.wrapped_path, {"PYTHONHOME": "$APPDIR/usr"}
        )
        expected = {
            "APPDIR": "$ORIGIN/.",
            "EXEC": "$APPDIR/bash.orig",
            "EXEC_ARGS": ["$@"],
            "APPDIR_LIBRARY_PATH": "$APPDIR/usr/lib",
            "PYTHONHOME": "$APPDIR/usr",
        }

        self.assertEqual(result, expected)


class TestExecutablesWrapperEnvSerializer(TestCase):
    def test_serialize_dict_to_dot_env(self):
        serialized_env = ExecutablesWrapper._serialize_dict_to_dot_env(
            {
                "APPDIR": "/AppDir",
                "APPIMAGE_UUID": "123",
                "EXEC_ARGS": ["-f", "$@"],
                "LIST": ["1", "2"],
                "DICT": {
                    "a": "b",
                    "c": "d",
                },
            }
        )

        self.assertEqual(
            serialized_env,
            "APPDIR=/AppDir\n"
            "APPIMAGE_UUID=123\n"
            "EXEC_ARGS=-f $@\n"
            "LIST=1:2\n"
            "DICT=a:b;c:d;\n",
        )
