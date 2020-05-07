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
import subprocess


class AppRuntimeAnalyser:
    def __init__(self, app_dir, bin, args):
        self.abs_app_dir = os.path.abspath(app_dir)
        self.bin = os.path.join(self.abs_app_dir, bin)
        self.args = args
        self.runtime_libs = set()
        self.logger = logging.getLogger('AppRuntimeAnalyser')

    def run_app_analysis(self):
        self.runtime_libs.clear()

        env = os.environ.copy()
        env['LD_DEBUG'] = 'libs'
        self.logger.debug("Running: %s %s" % (self.bin, self.args))
        process = subprocess.Popen([self.bin, self.args], stderr=subprocess.PIPE, env=env)

        while process.poll() is None:
            stderr_line = process.stderr.readline()
            while stderr_line:
                stderr_line = stderr_line.decode('utf-8').strip()
                path_start = stderr_line.find('init: ')
                if path_start != -1:
                    lib_path = stderr_line[path_start + len('init: '):]
                    lib_path = lib_path.strip()

                    if not lib_path.startswith(self.abs_app_dir):
                        self.runtime_libs.add(lib_path)
                        self.logger.debug("Runtime lib found: %s" % lib_path)

                stderr_line = process.stderr.readline()

        process.stderr.close()
