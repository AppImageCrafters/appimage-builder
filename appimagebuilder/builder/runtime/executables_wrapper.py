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
import logging
import os
import shutil
from pathlib import Path

from appimagebuilder.builder.runtime.apprun_binaries_resolver import (
    AppRunBinariesResolver,
)
from appimagebuilder.builder.runtime.environment import Environment
from appimagebuilder.builder.runtime.executables import (
    Executable,
    BinaryExecutable,
    InterpretedExecutable,
)
from appimagebuilder.common import file_utils


class ExecutablesWrapper:
    EXPORTED_FILES_PREFIX = "/tmp/appimage-"

    def __init__(
        self,
        appdir_path: str,
        binaries_resolver: AppRunBinariesResolver,
        env: Environment,
    ):
        self.appdir_path = Path(appdir_path)
        self.binaries_resolver = binaries_resolver
        self.env = env

    def wrap(self, executable: Executable):
        if self.is_wrapped(executable.path):
            return

        if isinstance(executable, BinaryExecutable):
            self._wrap_binary_executable(executable)

        if isinstance(executable, InterpretedExecutable):
            self._wrap_interpreted_executable(executable)

    def _wrap_binary_executable(self, executable):
        wrapped_path = str(executable.path) + ".orig"
        os.rename(executable.path, wrapped_path)
        apprun_env = self._generate_executable_env(executable, wrapped_path)
        self._deploy_env(executable, apprun_env)
        self.deploy_apprun(executable.arch, executable.path)
        self.deploy_hooks_lib(executable.arch)

    def deploy_apprun(self, arch, target_path):
        apprun_path = self.binaries_resolver.resolve_executable(arch)
        shutil.copyfile(apprun_path, target_path, follow_symlinks=True)
        file_utils.set_permissions_rx_all(target_path)

    def deploy_hooks_lib(self, arch):
        if not "APPDIR_LIBRARY_PATH" in self.env:
            raise RuntimeError("Missing APPDIR_LIBRARY_PATH")

        source_path = self.binaries_resolver.resolve_hooks_library(arch)

        paths = self.env.get("APPDIR_LIBRARY_PATH")
        if len(paths) <= 0:
            raise RuntimeError(
                "Please make sure APPDIR_LIBRARY_PATH is properly defined"
            )

        target_path = paths[0]
        target_path = Path(target_path) / "libapprun_hooks.so"

        shutil.copy2(source_path, target_path, follow_symlinks=True)

    def is_wrapped(self, path):
        return path.name.endswith(".orig")

    def _deploy_env(self, executable, env):
        env_path = str(executable.path) + ".env"
        with open(env_path, "w") as f:
            result = Environment.serialize(env)
            result = result.replace(str(self.appdir_path), "$APPDIR")
            f.write(result)

    def _generate_executable_env(self, executable, wrapped_path):
        executable_dir = os.path.dirname(executable.path)
        apprun_env = {
            "APPDIR": "$ORIGIN/" + os.path.relpath(self.appdir_path, executable_dir),
            "APPIMAGE_UUID": None,
            "EXEC_PATH": "$APPDIR/" + os.path.relpath(wrapped_path, self.appdir_path),
            "EXEC_ARGS": executable.args,
        }

        # set defaults
        for k, v in self.env.items():
            apprun_env[k] = v

        # override defaults with the user_env
        for k, v in executable.env.items():
            apprun_env[k] = v

        for k in list(apprun_env.keys()):
            if not apprun_env[k]:
                del apprun_env[k]

        return apprun_env

    def _wrap_interpreted_executable(self, executable):
        self._rewrite_shebang_using_env(executable)

    def _rewrite_shebang_using_env(self, executable):
        logging.info("Replacing SHEBANG on: %s" % executable.path)
        local_env_path = "%s%s-env" % (
            self.EXPORTED_FILES_PREFIX,
            self.env.get("APPIMAGE_UUID"),
        )
        tmp_path = executable.path.__str__() + ".tmp"
        output = open(tmp_path, "wb")
        try:
            with open(executable.path, "rb") as source:
                self._write_rel_shebang(executable, local_env_path, output)

                shebang_end = self.find_shebang_end(source, tmp_path)
                source.seek(shebang_end, 0)
                shutil.copyfileobj(source, output)

            executable.path.unlink()
            file_utils.set_permissions_rx_all(tmp_path)
            os.rename(tmp_path, executable.path)
        except:
            raise
        finally:
            output.close()

    def _write_rel_shebang(self, executable, local_env_path, output):
        output.write(b"#!%s" % local_env_path.encode())
        shebang_main = executable.shebang[0]
        if shebang_main.startswith("/usr/bin/env") or shebang_main.startswith(
            self.EXPORTED_FILES_PREFIX
        ):
            args_start = 2
        else:
            args_start = 1
        bin_name = os.path.basename(executable.shebang[args_start - 1])
        output.write(b" ")
        output.write(bin_name.encode())

        for entry in executable.shebang[args_start:]:
            output.write(b" ")
            output.write(entry.encode())

    def find_shebang_end(self, f, orig_file):
        buf = f.read(128)
        if buf[0] != ord("#") or buf[1] != ord("!"):
            raise RuntimeError("Unable to find shebang on %s" % orig_file)

        shebang_end = buf.find(b"\n")
        if shebang_end == -1:
            raise RuntimeError("Unable to find shebang end on %s" % orig_file)

        return shebang_end
