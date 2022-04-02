#  Copyright  2022 Alexis Lopez Zubieta
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
import pathlib


class ExecutablesPatcherError(RuntimeError):
    pass


class ExecutablesPatcher:
    def __init__(self):
        self.used_interpreters_paths = {}
        self.logger = logging.getLogger("ExecutablesPatcher")

    def patch_interpreted_executable(self, path: pathlib.Path):
        try:
            with open(path, "r+") as f:
                shebang = f.readline()
                patched_shebang = self.make_bin_path_in_shebang_relative(shebang)

                f.seek(0)
                f.write(patched_shebang)

                self._register_interpreter_used_in_shebang(path, patched_shebang)
        except Exception as e:
            self.logger.warning("Unable to patch script shebang %s: %s", path, e)

    def _register_interpreter_used_in_shebang(self, executable_path, shebang):
        interpreter_path = self.read_interpreter_path_from_shebang(shebang)
        self.used_interpreters_paths[executable_path] = interpreter_path

    @staticmethod
    def read_interpreter_path_from_shebang(shebang):
        interpreter_path = shebang[2:].strip()
        interpreter_path = interpreter_path.split(" ")[0]
        return interpreter_path

    @staticmethod
    def make_bin_path_in_shebang_relative(shebang):
        shebang_len = len(shebang)
        idx = 2
        while shebang_len > idx and (shebang[idx] == "/" or shebang[idx] == " "):
            idx = idx + 1

        patched = shebang[:2] + " " * (idx - 2) + shebang[idx:]

        return patched
