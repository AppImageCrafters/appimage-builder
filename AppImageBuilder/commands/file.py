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


class FileError(RuntimeError):
    pass


class File(Command):
    def __init__(self):
        super().__init__('file')
        self.log_stdout = False
        self.log_command = False

    def query(self, path):
        self._run(['file', '-b', '--exclude', 'ascii', path])

        if self.return_code != 0:
            raise FileError('\n'.join(self.stderr))

        return '\n'.join(self.stdout)

    def is_executable_elf(self, path):
        output = self.query(path)
        result = ('ELF' in output) and ('executable' in output)
        return result
