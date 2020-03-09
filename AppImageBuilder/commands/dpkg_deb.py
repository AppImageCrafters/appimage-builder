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


class DpkgDebError(RuntimeError):
    pass


class DpkgDeb(Command):
    def __init__(self):
        super().__init__('dpkg-deb')
        self.log_stdout = False
        self.extracted_files = []

    def extract(self, deb_file, target_dir):
        command = [self.runnable, '-X', deb_file, target_dir]
        self._run(command)

        if self.return_code != 0:
            raise DpkgDebError("Package extraction failed")

        self.extracted_files.clear()
        for line in self.stdout:

            if line.startswith('./'):
                line = line[2:]
                self.extracted_files.append(line)

            if line:
                self.logger.debug('%s: %s' % (os.path.basename(deb_file), line))
