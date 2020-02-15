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


class YumDownloaderError(RuntimeError):
    pass


class YumDownloader(Command):
    def __init__(self):
        super().__init__('yumdownloader')

    def download(self, packages, dir, exclude=None):
        if exclude is None:
            exclude = []

        command = self._get_yum_download_command(packages, exclude, dir)
        self._run(command)
        if self.return_code != 0:
            raise YumDownloaderError('yumdownloader failed')

    def _get_yum_download_command(self, packages, exclude, dir):
        command = ['yumdownloader', '--resolve', '--destdir=%s' % dir]
        command.extend([['-x', pkg] for pkg in exclude])
        command.extend(packages)

        return command
