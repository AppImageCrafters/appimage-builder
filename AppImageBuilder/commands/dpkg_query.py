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

from .command import Command


class DpkgQueryError(RuntimeError):
    pass


class DpkgQuery(Command):
    def __init__(self):
        super().__init__('dpkg-query')
        self.log_stdout = False

    def search(self, files):
        command = [self.runnable, '-S']
        command.extend(files)
        self._run(command)

        if self.return_code != 0:
            raise DpkgQueryError("Package lockup failed")

        packages = set()
        for line in self.stdout:
            split = line.find(':')
            packages.add(line[:split])

        return packages
