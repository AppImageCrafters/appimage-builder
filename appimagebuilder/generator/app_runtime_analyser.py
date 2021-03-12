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
import shutil
import subprocess

from appimagebuilder.common.finder import Finder

from appimagebuilder.commands.patchelf import PatchElf, PatchElfError
from appimagebuilder.common import shell

DEPENDS_ON = ["strace", "patchelf"]


class AppRuntimeAnalyser:
    def __init__(self, app_dir, bin, args):
        self.appdir = os.path.abspath(app_dir)
        self.bin = os.path.join(self.appdir, bin)
        self.args = args
        self.runtime_libs = set()
        self.runtime_bins = set()
        self.runtime_data = set()
        self.logger = logging.getLogger("AppRuntimeAnalyser")
        self._deps = shell.resolve_commands_paths(DEPENDS_ON)

    def run_app_analysis(self):
        self.runtime_libs.clear()
        library_paths = self._resolve_appdir_library_paths()
        library_paths = ":".join(library_paths)

        command = "{strace} -f -e trace=openat -E LD_DEBUG=libs -E LD_LIBRARY_PATH={library_paths} {bin} {args}"
        command = command.format(
            bin=self.bin, args=self.args, **self._deps, library_paths=library_paths
        )

        self.logger.info(command)
        output = subprocess.run(command, stderr=subprocess.PIPE, shell=True)

        stderr_data = output.stderr.decode("utf-8")
        self.runtime_libs = re.findall("init: (?P<lib>/.*)", stderr_data, re.IGNORECASE)
        self.runtime_bins = re.findall(
            "program: (?P<bin>.*)", stderr_data, re.IGNORECASE
        )
        self.runtime_bins = [shutil.which(path) for path in self.runtime_bins]
        self.runtime_data = re.findall(
            r'openat\(.*?"(?P<path>.*?)".*', stderr_data, re.IGNORECASE
        )

        # remove dirs, non existent files and excluded paths
        self.runtime_data = [
            path
            for path in self.runtime_data
            if os.path.exists(path)
            and not os.path.isdir(path)
            and not self._is_excluded_data_path(path)
            and path not in self.runtime_bins
            and path not in self.runtime_libs
        ]

        interpreter_paths = self._resolve_bin_interpreters()
        self.runtime_bins.extend(interpreter_paths)

        self.runtime_bins = sorted(path for path in self.runtime_bins if not path.startswith(self.appdir))
        self.runtime_libs = sorted(path for path in self.runtime_libs if not path.startswith(self.appdir))
        self.runtime_data = sorted(path for path in self.runtime_data if not path.startswith(self.appdir))

        if not self.runtime_libs:
            logging.warning(
                "No dependencies were found, "
                "please make sure that all the required libraries are reachable."
            )

    def _resolve_appdir_library_paths(self):
        finder = Finder(self.appdir)
        lib_paths = finder.find("*", [Finder.is_elf_shared_lib])
        library_paths = set([os.path.dirname(path) for path in lib_paths])
        return library_paths

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
