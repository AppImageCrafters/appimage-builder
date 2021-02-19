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

import os
import shutil
import tempfile
from pathlib import Path
from unittest import TestCase

from appimagebuilder.builder.runtime.apprun_binaries_resolver import (
    AppRunBinariesResolver,
)
from appimagebuilder.builder.runtime.environment import Environment
from appimagebuilder.builder.runtime.executables import (
    Executable,
    BinaryExecutable,
    InterpretedExecutable,
)
from appimagebuilder.builder.runtime.executables_wrapper import ExecutablesWrapper


class FakeAppRunBinariesResolver(AppRunBinariesResolver):
    def __init__(self):
        super().__init__("", "Release")
        self.temp_file = Path("/tmp/fake-apprun")
        self.temp_file.touch()

    def resolve_executable(self, arch):
        return str(self.temp_file)

    def resolve_hooks_library(self, arch):
        return str(self.temp_file)


class TestExecutablesWrapper(TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)

        self.bin_path = self.data_dir / "bin"
        shutil.copy("/bin/bash", self.bin_path)

        self.script_path = self.data_dir / "script"
        with self.script_path.open("w") as f:
            f.write("#!/usr/bin/python3\n" "1234567890\n")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_wrap_binary_executable(self):
        resolver = FakeAppRunBinariesResolver()
        environment = Environment()
        environment.set("APPDIR_LIBRARY_PATH", [str(self.data_dir)])
        wrapper = ExecutablesWrapper(self.data_dir, resolver, environment)
        executable = BinaryExecutable(self.bin_path, "x86_64")
        wrapper.wrap(executable)

        self.assertTrue(os.access(self.bin_path, os.X_OK | os.R_OK))

        wrapped_path = self.bin_path.with_name("bin.orig")
        self.assertTrue(wrapped_path.exists())

        env_path = self.bin_path.with_name("bin.env")
        self.assertTrue(env_path.exists())

        libapprun_hooks_path = self.data_dir / "libapprun_hooks.so"
        self.assertTrue(libapprun_hooks_path.exists())

    def test_wrap_interpreted_executable(self):
        resolver = FakeAppRunBinariesResolver()
        environment = Environment()
        environment.set("APPIMAGE_UUID", "UUID")
        wrapper = ExecutablesWrapper(self.data_dir, resolver, environment)
        executable = InterpretedExecutable(self.script_path, ["/usr/bin/python3"])
        wrapper.wrap(executable)

        result = self.script_path.read_text()
        expected = "#!/tmp/appimage-UUID-env python3\n" "1234567890\n"
        self.assertTrue(os.access(self.bin_path, os.X_OK | os.R_OK))

        self.assertEqual(expected, result)

    def test_wrap_previously_wrpped_interpreted_executable(self):
        resolver = FakeAppRunBinariesResolver()
        environment = Environment()
        environment.set("APPIMAGE_UUID", "UUID")
        wrapper = ExecutablesWrapper(self.data_dir, resolver, environment)
        executable = InterpretedExecutable(
            self.script_path, ["/tmp/appimage-OLD-UUID-env", "python3"]
        )
        wrapper.wrap(executable)

        result = self.script_path.read_text()
        expected = "#!/tmp/appimage-UUID-env python3\n" "1234567890\n"
        self.assertTrue(os.access(self.bin_path, os.X_OK | os.R_OK))

        self.assertEqual(expected, result)

    def test_generate_executable_env(self):
        resolver = FakeAppRunBinariesResolver()
        environment = Environment()
        environment.set("APPDIR_LIBRARY_PATH", [self.data_dir / "usr/lib"])
        environment.set("APPIMAGE_UUID", "1234")
        executable = Executable(self.bin_path)
        executable.env = {"PYTHONHOME": "$APPDIR/usr"}
        wrapper = ExecutablesWrapper(self.data_dir, resolver, environment)
        result = wrapper._generate_executable_env(
            executable, self.bin_path.with_name("bin.orig")
        )
        expected = {
            "APPDIR": "$ORIGIN/.",
            "APPIMAGE_UUID": "1234",
            "EXEC_PATH": "$APPDIR/bin.orig",
            "EXEC_ARGS": ["$@"],
            "APPDIR_LIBRARY_PATH": [self.data_dir / "usr/lib"],
            "PYTHONHOME": "$APPDIR/usr",
        }

        self.assertEqual(result, expected)
