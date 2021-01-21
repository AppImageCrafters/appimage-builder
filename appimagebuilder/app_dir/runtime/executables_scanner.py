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
import os
import subprocess

from appimagebuilder.app_dir.file_info_cache import FileInfoCache
from appimagebuilder.app_dir.runtime.executables import Executable, BinaryExecutable, InterpretedExecutable
from appimagebuilder.common.file_test import read_elf_arch


class ExecutablesScanner:
    def __init__(self, appdir, files_cache: FileInfoCache):
        self.appdir = appdir
        self.files_cache = files_cache

    def scan_file(self, path) -> [Executable]:
        results = []
        iterations = 0
        for iterations in range(1, 5):
            shebang = ExecutablesScanner.read_shebang(path)
            if shebang:
                results.append(InterpretedExecutable(path, shebang))
                path = self._resolve_interpreter_path(shebang)
            else:
                arch = read_elf_arch(path)
                results.append(BinaryExecutable(path, arch))
                break

        if iterations >= 5:
            raise RuntimeError("Loop found while resolving the interpreter of '%s'" % path)

        return results

    def _resolve_interpreter_path(self, shebang):
        if shebang[0] == "/usr/bin/env":
            bin_name = shebang[1]
            path = self.files_cache.find_one("*/%s" % bin_name, [])
            if not path:
                raise RuntimeError("Required binary '%s' could not be found in the AppDir")
            return path
        else:
            path = shebang[0]
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
            return parts
