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
import stat

from packaging import version
from functools import reduce

from appimagebuilder.common.file_test import is_elf
from .base_helper import BaseHelper
from appimagebuilder.commands.patchelf import PatchElf, PatchElfError


class InterpreterHandlerError(RuntimeError):
    pass


class Interpreter(BaseHelper):
    def __init__(self, app_dir, app_dir_cache):
        super().__init__(app_dir, app_dir_cache)

        self.priority = 100
        self.patch_elf = PatchElf()
        self.patch_elf.logger.level = logging.WARNING
        self.interpreters = {}

    def get_glibc_path(self) -> str:
        paths = self.app_dir_cache.find("*/libc.so.*")
        if not paths:
            raise InterpreterHandlerError("Unable to find libc.so")
        path = paths[0]

        logging.info("Libc found at: %s" % os.path.relpath(path, self.app_dir))
        return path

    def configure(self, app_run):
        app_run.env["PATH"] = ":".join(
            ["$APPDIR/%s:$PATH" % path for path in self._get_bin_paths()]
        )

        app_run.env["APPDIR_LIBRARY_PATH"] = ":".join(
            ["$APPDIR/%s" % path for path in self._get_appdir_library_paths()]
        )
        app_run.env["LIBC_LIBRARY_PATH"] = ":".join(
            ["$APPDIR/%s" % path for path in self._get_libc_library_paths()]
        )

        glibc_path = self.get_glibc_path()
        glibc_version = self.gess_libc_version(glibc_path)
        app_run.env["APPDIR_LIBC_VERSION"] = glibc_version

        self._patch_executables_interpreter(app_run.env["APPIMAGE_UUID"])
        app_run.env["SYSTEM_INTERP"] = ":".join(self.interpreters.keys())

    @staticmethod
    def _is_linker_file(file):
        return fnmatch.fnmatch(file, "*/ld-*.so*")

    def _get_appdir_library_paths(self):
        paths = self.app_dir_cache.find("*", attrs=["is_lib"])
        # only dir names are relevant
        paths = set(os.path.dirname(path) for path in paths)

        # make all paths relative to app_dir
        paths = [os.path.relpath(path, self.app_dir) for path in paths]

        # exclude libc partition paths
        paths = [path for path in paths if not path.startswith("opt/libc")]

        # exclude qt5 plugins paths
        paths = [path for path in paths if "qt5/plugins" not in path]

        # exclude perl paths
        paths = [path for path in paths if "/perl/" not in path]
        paths = [path for path in paths if "/perl-base/" not in path]

        return paths

    def _get_libc_library_paths(self):
        paths = self.app_dir_cache.find("*", attrs=["is_lib"])

        # only dir names are relevant
        paths = set(os.path.dirname(path) for path in paths)

        # make all paths relative to app_dir
        paths = [os.path.relpath(path, self.app_dir) for path in paths]

        # exclude libc partition paths
        paths = [path for path in paths if path.startswith("opt/libc")]

        return paths

    def _load_ld_conf_file(self, file):
        paths = set()
        with open(file, "r") as fin:
            for line in fin.readlines():
                if line.startswith("/"):
                    paths.add(line.strip())
        return paths

    def _set_execution_permissions(self, path):
        os.chmod(
            path,
            stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH,
        )

    def gess_libc_version(self, loader_path):
        glib_version_re = re.compile(r"GLIBC_(?P<version>\d+\.\d+\.?\d*)")
        with open(loader_path, "rb") as f:
            content = str(f.read())
            glibc_version_strings = glib_version_re.findall(content)
            if glibc_version_strings:
                glibc_version_strings = map(version.parse, glibc_version_strings)
                max_glibc_version = reduce(
                    (lambda x, y: max(x, y)), glibc_version_strings
                )
                return str(max_glibc_version)
            else:
                raise InterpreterHandlerError("Unable to determine glibc version")

    def _patch_executables_interpreter(self, uuid):
        for bin in self.app_dir_cache.find("*", attrs=["pt_interp"]):
            self._set_interpreter(bin, uuid)

    def _set_interpreter(self, file, uuid):
        real_interpreter = self.app_dir_cache.cache[file]["pt_interp"]
        if real_interpreter.startswith("/tmp/appimage-"):
            # skip, the binary has been patched already
            return
        try:
            patchelf_command = PatchElf()
            patchelf_command.log_stderr = False
            patchelf_command.log_stdout = False

            apprun_interpreter = self._gen_interpreter_link_path(real_interpreter, uuid)
            if real_interpreter and real_interpreter != apprun_interpreter:
                self.interpreters[real_interpreter] = apprun_interpreter
                logging.info(
                    "Replacing PT_INTERP on: %s" % os.path.relpath(file, self.app_dir)
                )
                logging.info('\t"%s"  => "%s"' % (real_interpreter, apprun_interpreter))
                patchelf_command.set_interpreter(file, apprun_interpreter)
                self.app_dir_cache.cache[file]["pt_interp"] = apprun_interpreter
        except PatchElfError:
            pass

    @staticmethod
    def _gen_interpreter_link_path(real_interpreter, uuid):
        return "/tmp/appimage-%s-%s" % (uuid, os.path.basename(real_interpreter))

    def _get_bin_paths(self):
        paths = self.app_dir_cache.find("*", attrs=["is_bin"])
        # only dir names are relevant
        paths = set(os.path.dirname(path) for path in paths)

        # make all paths relative to app_dir
        paths = [os.path.relpath(path, self.app_dir) for path in paths]

        # exclude libc partition paths
        paths = [path for path in paths if not path.startswith("opt/libc")]

        return paths
