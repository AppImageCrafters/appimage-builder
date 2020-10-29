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
import fnmatch
import logging
import os
import re
import subprocess

from AppImageBuilder.commands.patchelf import PatchElf, PatchElfError


class AppRuntimeAnalyser:
    def __init__(self, app_dir, bin, args):
        self.abs_app_dir = os.path.abspath(app_dir)
        self.bin = os.path.join(self.abs_app_dir, bin)
        self.args = args
        self.runtime_libs = set()
        self.runtime_bins = set()
        self.runtime_data = set()
        self.logger = logging.getLogger("AppRuntimeAnalyser")

    def run_app_analysis(self):
        self.runtime_libs.clear()

        self.logger.debug("Running: %s %s" % (self.bin, self.args))
        process = subprocess.Popen(
            [
                "strace",
                "-f",
                "-e",
                "trace=openat",
                "-E",
                "LD_DEBUG=libs",
                self.bin,
                self.args,
            ],
            stderr=subprocess.PIPE,
        )

        while process.poll() is None:
            stderr_line = process.stderr.readline()
            while stderr_line:
                stderr_line = stderr_line.decode("utf-8").strip()
                self.runtime_libs.add(self._read_lib_path(stderr_line))
                self.runtime_bins.add(self._read_bin_path(stderr_line))
                self.runtime_data.add(self._read_data_path(stderr_line))
                stderr_line = process.stderr.readline()

        self.runtime_libs.remove(None)
        self.runtime_bins.remove(None)
        self.runtime_data.remove(None)

        interpreter_paths = self._resolve_bin_interpreters()
        self.runtime_bins = self.runtime_bins.union(interpreter_paths)

        self.runtime_bins = sorted(self.runtime_bins)
        self.runtime_libs = sorted(self.runtime_libs)
        self.runtime_data = sorted(self.runtime_data)

        process.stderr.close()

    def _resolve_bin_interpreters(self):
        patch_elf = PatchElf()
        patch_elf.log_stderr = False
        interpreter_paths = set()
        for bin in self.runtime_bins:
            try:
                interpreter = patch_elf.get_interpreter(bin)
                if not interpreter.startswith("/tmp"):
                    interpreter_paths.add(interpreter)
            except PatchElfError:
                pass
        return interpreter_paths

    @staticmethod
    def _read_lib_path(stderr_line):
        lib_path_search = re.search("init: (?P<lib>/.*)", stderr_line, re.IGNORECASE)
        if lib_path_search:
            return lib_path_search.group(1)
        return None

    @staticmethod
    def _read_bin_path(stderr_line):
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

    @staticmethod
    def _read_data_path(stderr_line):

        data_path_search = re.search(
            r'openat\(.*?"(?P<path>.*?)".*', stderr_line, re.IGNORECASE
        )

        if data_path_search:
            path = data_path_search.group(1)

            if (
                os.path.exists(path)
                and not os.path.isdir(path)
                and not AppRuntimeAnalyser._is_excluded_data_path(path)
            ):
                return path

        return None

    @staticmethod
    def _is_excluded_data_path(path):
        excluded_data_paths = [
            os.getenv("HOME") + "/*",
            "/sys/*",
            "/proc/*",
            "/dev/*",
            "/etc/ld.so.cache",
            "/etc/nsswitch.conf",
            "/etc/passwd",
            "*/.local/*",
            "*/.fonts/*",
            "*/.cache/*",
            "*/.config/*",
            "*/locale.alias",
            "/var/lib/dbus/*",
            "/usr/local/share/fonts",
            "/usr/share/fonts/*",
            "/var/cache/fontconfig",
            "/var/cache/fontconfig/*",
        ]

        for expr in excluded_data_paths:
            if fnmatch.fnmatch(path, expr):
                return True

        return False
