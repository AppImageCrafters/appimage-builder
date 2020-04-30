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
from shutil import which
import subprocess


class Command:
    class CommandMissingError(RuntimeError):
        pass

    def __init__(self, runnable, logger=None):
        self.runnable = which(runnable)
        self.assert_runnable_exists(runnable)

        self.log_command = True
        self.log_stdout = True
        self.log_stderr = True
        self.env = os.environ.copy()

        self.logger = logger
        if not self.logger:
            self.logger = logging.getLogger(runnable)

        self.return_code = None
        self.stdout = []
        self.stderr = []
        self.cwd = os.path.curdir

    @staticmethod
    def assert_runnable_exists(runnable):
        if not runnable:
            raise Command.CommandMissingError('Unable to locate \'%s\' runnable. Please make sure it is installed '
                                              'and available in the environment variable PATH.' % runnable)

    def _run(self, command):
        self.stdout.clear()
        self.stderr.clear()

        if self.log_command:
            self.logger.info(' '.join(command))
        else:
            self.logger.debug(' '.join(command))

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.cwd, env=self.env)

        self._poll_process(process)

    def _run_with_input(self, command, input):
        self.logger.info(' '.join(command))
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=self.cwd)
        process.communicate(input)

        self._poll_process(process)

    def _poll_process(self, process):
        while process.poll() is None:
            self._process_stdout_lines(process)
            self._process_stderr_lines(process)

        process.stdout.close()
        process.stderr.close()

        self.return_code = process.poll()

    def _process_stderr_lines(self, process):
        stderr_line = process.stderr.readline()
        while stderr_line:
            stderr_line = stderr_line.decode('utf-8').strip()
            self.stderr.append(stderr_line)
            if self.log_stderr:
                self.logger.warning(stderr_line)

            stderr_line = process.stderr.readline()

    def _process_stdout_lines(self, process):
        stdout_line = process.stdout.readline()
        while stdout_line:
            stdout_line = stdout_line.decode('utf-8').strip()
            self.stdout.append(stdout_line)
            if self.log_stdout:
                self.logger.info(stdout_line)

            stdout_line = process.stdout.readline()
