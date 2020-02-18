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

from .command import Command


class PatchElfError(RuntimeError):
    pass


class PatchElf(Command):
    def __init__(self):
        super().__init__('patchelf')

    def get_interpreter(self, file):
        self._run(['patchelf', '--print-interpreter', file])
        if self.return_code != 0:
            raise PatchElfError('\n'.join(self.stderr))

        return '\n'.join(self.stdout).strip()

    def set_interpreter(self, file, interpreter):
        self._run(['patchelf', '--set-interpreter', interpreter, file])

        if self.return_code != 0:
            raise PatchElfError('\n'.join(self.stderr))

    def get_needed(self, file):
        self._run(['patchelf', '--print-needed', file])

        if self.return_code != 0:
            raise PatchElfError('\n'.join(self.stderr))

        return self.stdout

    def set_run_path(self, file, run_paths):
        self._run(['patchelf', '--set-rpath', ':'.join(run_paths), file])

        if self.return_code != 0:
            raise PatchElfError('\n'.join(self.stderr))

    def set(self, file, run_path=None, interpreter=None):
        command = ['patchelf']
        if run_path:
            command.append('--set-rpath')
            command.append(':'.join(run_path))

        if interpreter:
            command.append('--set-interpreter')
            command.append(interpreter)

        command.append(file)
        self._run(command)

        if self.return_code != 0:
            raise PatchElfError('\n'.join(self.stderr))
