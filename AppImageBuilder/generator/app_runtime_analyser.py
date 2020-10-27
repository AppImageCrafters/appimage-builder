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
import re
import subprocess


class AppRuntimeAnalyser:
    def __init__(self, app_dir, bin, args):
        self.abs_app_dir = os.path.abspath(app_dir)
        self.bin = os.path.join(self.abs_app_dir, bin)
        self.args = args
        self.runtime_libs = set()
        self.runtime_bins = set()
        self.logger = logging.getLogger("AppRuntimeAnalyser")

    def run_app_analysis(self):
        self.runtime_libs.clear()

        env = os.environ.copy()
        env["LD_DEBUG"] = "libs"
        self.logger.debug("Running: %s %s" % (self.bin, self.args))
        process = subprocess.Popen(
            [self.bin, self.args], stderr=subprocess.PIPE, env=env
        )

        while process.poll() is None:
            stderr_line = process.stderr.readline()
            while stderr_line:
                stderr_line = stderr_line.decode("utf-8").strip()
                self.runtime_libs.add(self._extract_lib_path(stderr_line))
                self.runtime_bins.add(self._extract_bin_path(stderr_line))

                stderr_line = process.stderr.readline()

        self.runtime_libs.remove(None)
        self.runtime_bins.remove(None)

        process.stderr.close()

    @staticmethod
    def _extract_lib_path(stderr_line):
        lib_path_search = re.search("init: (?P<lib>/.*)", stderr_line, re.IGNORECASE)
        if lib_path_search:
            return lib_path_search.group(1)
        return None

    @staticmethod
    def _extract_bin_path(stderr_line):
        bin_path_search = re.search("program: (?P<bin>.*)", stderr_line, re.IGNORECASE)
        if bin_path_search:
            bin_name = bin_path_search.group(1)
            if os.path.exists(bin_name):
                return bin_name
            else:
                for path in os.getenv("PATH").split(":"):
                    full_path = os.path.join(path, bin_name)
                    if os.path.exists(full_path):
                        return full_path

        return None
