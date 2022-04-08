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

from appimagebuilder.utils.command import Command


class PatchElfError(RuntimeError):
    pass


class PatchElf(Command):
    def __init__(self):
        super().__init__("patchelf")

    def get_interpreter(self, file):
        file = file.__str__()
        self._run(["patchelf", "--print-interpreter", file])
        if self.return_code != 0:
            raise PatchElfError("\n".join(self.stderr))

        return "\n".join(self.stdout).strip()

    def set_interpreter(self, file, interpreter):
        file = file.__str__()
        self._run(["patchelf", "--set-interpreter", interpreter, file])

        if self.return_code != 0:
            raise PatchElfError("\n".join(self.stderr))

    def get_needed(self, file):
        file = file.__str__()
        self._run(["patchelf", "--print-needed", file])

        if self.return_code != 0:
            raise PatchElfError("\n".join(self.stderr))

        return self.stdout

    def get_rpath(self, file):
        file = file.__str__()
        self._run(["patchelf", "--print-rpath", file])

        if self.return_code != 0:
            raise PatchElfError("\n".join(self.stderr))

        return "".join(self.stdout).split(":")

    def set_rpath(self, file: str, run_paths: [str]):
        file = file.__str__()
        command = ["patchelf", "--set-rpath", ":".join(run_paths), file]
        self._run(command)

        if self.return_code != 0:
            raise PatchElfError("\n".join(self.stderr))

    def get_soname(self, file):
        file = file.__str__()
        self._run(["patchelf", "--print-soname", file])

        if self.return_code != 0:
            raise PatchElfError("\n".join(self.stderr))

        return self.stdout

    def set(self, file, run_path=None, interpreter=None):
        file = file.__str__()
        command = ["patchelf"]
        if run_path:
            command.append("--set-rpath")
            command.append(":".join(run_path))

        if interpreter:
            command.append("--set-interpreter")
            command.append(interpreter)

        command.append(file)
        self._run(command)

        if self.return_code != 0:
            raise PatchElfError("\n".join(self.stderr))

    def add_needed(self, file, lib_needed):
        file = file.__str__()
        self._run(["patchelf", "--add-needed", lib_needed, file])

        if self.return_code != 0:
            raise PatchElfError("\n".join(self.stderr))
