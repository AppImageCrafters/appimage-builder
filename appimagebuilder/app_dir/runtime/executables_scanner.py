#  Copyright  2020 Alexis Lopez Zubieta
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

from appimagebuilder.app_dir.file_info_cache import FileInfoCache
from appimagebuilder.app_dir.runtime.executables import (
    Executable,
    BinaryExecutable,
    InterpretedExecutable,
)
from appimagebuilder.common import file_utils


class MissingInterpreterError(RuntimeError):
    pass


class ExecutablesScanner:
    def __init__(self, appdir, files_cache: FileInfoCache):
        self.appdir = appdir
        self.files_cache = files_cache

    def scan_file(self, path) -> [Executable]:
        results = []
        iterations = 0
        binary_found = False
        while iterations < 5 and not binary_found:
            shebang = ExecutablesScanner.read_shebang(path)
            if shebang:
                try:
                    executable = InterpretedExecutable(path, shebang)
                    path = self._resolve_interpreter_path(shebang)
                except MissingInterpreterError as err:
                    logging.warning(err.__str__() + " while processing " + path)
                    break
            else:
                if file_utils.is_elf_executable(path):
                    arch = file_utils.read_elf_arch(path)
                    executable = BinaryExecutable(path, arch)
                    binary_found = True
                else:
                    break

            if len(results) > 0:
                results[-1].interpreter = executable

            results.append(executable)
            iterations = iterations + 1

        if iterations >= 5:
            raise RuntimeError(
                "Loop found while resolving the interpreter of '%s'" % path
            )

        return results

    def _resolve_interpreter_path(self, shebang):
        if shebang[0] == "/usr/bin/env":
            interpreter_path = shebang[1].strip(" ")
            interpreter_name = os.path.basename(interpreter_path)
            path = self.files_cache.find_one("*/%s" % interpreter_name)
            if not path:
                raise RuntimeError(
                    "Required binary '%s' could not be found in the AppDir" % path
                )

            path = os.path.relpath(path)
            if not path:
                raise RuntimeError(
                    "Required binary '%s' could not be found in the AppDir" % path
                )
            return path
        else:
            path = self.appdir / shebang[0].strip("/")
            path = os.path.realpath(path)
            if not os.path.exists(path):
                raise MissingInterpreterError(
                    "Required binary '%s' could not be found in the AppDir" % path
                )
        return path

    @staticmethod
    def read_shebang(path) -> [str]:
        with open(path, "rb") as f:
            buf = f.read(128)

            if buf[0] != ord("#") or buf[1] != ord("!"):
                return None

            end_idx = buf.find(b"\n")
            if end_idx == -1:
                end_idx = len(buf)

            buf = buf[2:end_idx].decode()

            parts = buf.split(" ")
            parts = [part.strip() for part in parts if part]
            return parts
