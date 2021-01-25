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
import stat
from pathlib import Path

from appimagebuilder.app_dir.runtime.apprun_binaries_resolver import (
    AppRunBinariesResolver,
)
from appimagebuilder.app_dir.runtime.environment import GlobalEnvironment, Environment
from appimagebuilder.app_dir.runtime.executables import (
    Executable,
    BinaryExecutable,
    InterpretedExecutable,
)


class ExecutablesWrapper:
    def __init__(
        self,
        appdir_path: str,
        binaries_resolver: AppRunBinariesResolver,
        env: GlobalEnvironment,
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
            self._rewrite_shebang_using_env(executable)

    def _wrap_binary_executable(self, executable):
        wrapped_path = str(executable.path) + ".orig"
        os.rename(executable.path, wrapped_path)
        apprun_env = self._generate_executable_env(executable, wrapped_path)
        self._deploy_env(executable, wrapped_path, apprun_env)
        self.deploy_apprun(executable.arch, executable.path)
        self.deploy_hooks_lib(executable.arch)

    def deploy_apprun(self, arch, target_path):
        apprun_path = self.binaries_resolver.resolve_executable(arch)
        shutil.copyfile(apprun_path, target_path, follow_symlinks=True)
        self._set_execution_permissions(target_path)

    def deploy_hooks_lib(self, arch):
        if not "APPDIR_LIBRARY_PATH" in self.env:
            raise RuntimeError("Missing APPDIR_LIBRARY_PATH")

        paths = self.env.get("APPDIR_LIBRARY_PATH")
        source_path = self.binaries_resolver.resolve_hooks_library(arch)
        target_path = Path(paths[0]) / "libapprun_hooks.so"
        shutil.copy2(source_path, target_path, follow_symlinks=True)

    def _remove_binary_only_variables(self, apprun_env):
        binary_only_vars = [
            "LD_PRELOAD",
            "APPDIR_LIBRARY_PATH",
            "LIBC_LIBRARY_PATH",
            "APPDIR_LIBC_VERSION",
            "SYSTEM_INTERP",
        ]
        for var in binary_only_vars:
            if var in apprun_env:
                del apprun_env[var]

    def _set_execution_permissions(self, path):
        os.chmod(
            path,
            stat.S_IRUSR
            | stat.S_IRGRP
            | stat.S_IROTH
            | stat.S_IXUSR
            | stat.S_IXGRP
            | stat.S_IXOTH,
        )

    def _rewrite_shebang_using_env(self, executable):
        logging.info("Patching shebang on script: %s" % executable.path)
        local_env_path = "/tmp/appimage-" + self.env.get("APPIMAGE_UUID") + "-env"
        tmp_path = executable.path.__str__() + ".tmp"
        output = open(tmp_path, "wb")
        try:
            with open(executable.path, "rb") as source:
                self._write_rel_shebang(executable, local_env_path, output)

                shebang_end = self.find_shebang_end(source, tmp_path)
                source.seek(shebang_end, 0)
                shutil.copyfileobj(source, output)

            executable.path.unlink()
            self._set_execution_permissions(tmp_path)
            os.rename(tmp_path, executable.path)
        except:
            raise
        finally:
            output.close()

    def _write_rel_shebang(self, executable, local_env_path, output):
        output.write(b"#!%s" % local_env_path.encode())
        args_start = 2 if executable.shebang[0] == "/usr/bin/env" else 1
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

    def is_wrapped(self, path):
        return path.name.endswith(".orig")

    def _deploy_env(self, executable, wrapped_path, env):
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
