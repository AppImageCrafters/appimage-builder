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
import pathlib
import re
import subprocess

from appimagebuilder.utils.patchelf import PatchElf, PatchElfError
from appimagebuilder.utils import shell
from appimagebuilder.utils.finder import Finder

DEPENDS_ON = ["strace", "patchelf"]


class AppRuntimeAnalyser:
    def __init__(self):
        self.logger = logging.getLogger("AppRuntimeAnalyser")
        self._deps = shell.resolve_commands_paths(DEPENDS_ON)

    def run_app_analysis(self, app_dir: pathlib.Path, exec: str, exec_args: str):
        full_exec_path = app_dir / exec
        accessed_files = self._trace_file_access(app_dir, full_exec_path, exec_args)

        # remove dirs, non existent files and excluded paths
        accessed_files = [
            path
            for path in accessed_files
            if os.path.exists(path)
            and not os.path.isdir(path)
            and not self._is_excluded_data_path(path)
        ]

        # include the main executable in the list
        accessed_files.append(full_exec_path)

        # include binary interpreters in the list
        interpreter_paths = self._resolve_bin_interpreters(accessed_files)
        accessed_files.extend(interpreter_paths)

        # exclude files from the bundle
        accessed_files = [
            path for path in accessed_files if not str(path).startswith(str(app_dir))
        ]
        return accessed_files

    def _trace_file_access(self, app_dir, exec_path, exec_args):
        """Execute the application using strace to find which files are accessed at runtime"""

        # find dirs containing libraries that may be needed by the application at runtime
        library_paths = self._resolve_appdir_library_paths(app_dir)
        library_paths = ":".join(library_paths)

        # use strace to discover which files are accessed at runtime
        # arguments:
        #   "-f" trace children processes
        #   "-E LD_LIBRARY_PATH={library_paths}" set LD_LIBRARY_PATH in the application environment
        #   "-e trace=openat --status=successful" trace file access operations that succeed
        command = "{strace} -f -E LD_LIBRARY_PATH={library_paths} -e trace=openat --status=successful {bin} {args}"
        command = command.format(
            bin=exec_path, args=exec_args, **self._deps, library_paths=library_paths
        )
        self.logger.info(command)
        _proc = subprocess.run(command, stderr=subprocess.PIPE, shell=True)

        if _proc.returncode != 0:
            self.logger.warning(
                "%s exited with code %d" % (_proc.args, _proc.returncode)
            )
            self.logger.warning(
                "This may produce an incomplete/wrong recipe. Please make sure that the application runs properly."
            )

        # parse results
        stderr_data = _proc.stderr.decode()
        return self._parse_strace_results(stderr_data)

    @staticmethod
    def _parse_strace_results(stderr_data):
        openat_calls = re.findall(r'openat\(.*?"(?P<path>.*?)".*', stderr_data)
        stat_calls = re.findall(r'stat\(.*?"(?P<path>.*?)".*', stderr_data)
        return [*openat_calls, *stat_calls]

    def _resolve_appdir_library_paths(self, app_dir):
        finder = Finder(app_dir)
        lib_paths = finder.find("*", [Finder.is_elf_shared_lib])
        library_paths = set([os.path.dirname(path) for path in lib_paths])
        return library_paths

    def _resolve_bin_interpreters(self, executable_files):
        self.logger.info("Reading PT_INTERP from executables")
        patch_elf = PatchElf()
        patch_elf.log_command = False
        patch_elf.log_stdout = False
        patch_elf.log_stderr = False

        interpreter_paths = set()
        for path in executable_files:
            try:
                interpreter = patch_elf.get_interpreter(path)
                if not interpreter.startswith("/tmp"):
                    interpreter_paths.add(interpreter)
            except PatchElfError:
                pass
        return interpreter_paths

    @staticmethod
    def _is_excluded_data_path(path):
        excluded_data_paths = [
            # don't include virtual fs
            "/sys/**",
            "/proc/**",
            "/dev/**",
            "/run/**",
            # don't include system settings
            "/etc/**",
            # don't include user settings or cache
            os.getenv("HOME") + "/.cache/*",
            os.getenv("HOME") + "/.config/*",
            os.getenv("HOME") + "/.Xauthority",
            # don't include dbus as it will not be reachable from the bundle
            "/var/lib/dbus/*",
            # do not include font files
            "**/fonts/*.conf",
            "**/fonts/*.otf",
            "**/fontconfig/**/*.conf",
            "**/fontconfig/**/*.cache*",
            os.getenv("HOME") + "/.fonts/*",
            # don't include GTK caches
            "**/gdk-pixbuf-2.0/**/loaders.cache",
            "**/gio/**/giomodule.cache",
            "**/glib-2.0/**/gschemas.compiled",
        ]

        for expr in excluded_data_paths:
            if fnmatch.fnmatch(path, expr):
                return True

        return False
