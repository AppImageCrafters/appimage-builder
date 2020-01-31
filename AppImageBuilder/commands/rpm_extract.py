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
import subprocess

from .command import Command


class RpmExtractError(RuntimeError):
    pass


class RpmExtract(Command):
    def __init__(self):
        super().__init__('rpm2cpio')
        Command.assert_runnable_exists('cpio')

        self.log_stdout = False
        self.log_stderr = False

    def extract(self, rpm_file, target_dir):
        command = self._get_rpm_extract_command(rpm_file)
        subprocess.run(command, shell=True, check=True, cwd=target_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _get_rpm_extract_command(self, rpm_file):
        return 'rpm2cpio %s | cpio -idmv' % rpm_file
