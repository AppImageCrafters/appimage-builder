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
import pathlib
import re
import stat
from distutils.command.check import check
from functools import reduce

from packaging import version

from appimagebuilder.commands.patchelf import PatchElf, PatchElfError
from appimagebuilder.common.finder import Finder
from .base_helper import BaseHelper
from ..environment import Environment


class InterpreterHandlerError(RuntimeError):
    pass


class Interpreter(BaseHelper):
    def __init__(self, app_dir, finder):
        super().__init__(app_dir, finder)

        self.priority = 100
        self.patch_elf = PatchElf()
        self.patch_elf.logger.level = logging.WARNING
        self.interpreters = {}

    def get_glibc_path(self) -> str:
        path = self.finder.find_one("*/libc.so.*", [Finder.is_elf_shared_lib])
        if not path:
            raise InterpreterHandlerError("Unable to find libc.so")

        logging.info("Libc found at: %s" % os.path.relpath(path, self.app_dir))
        return path

    def configure(self, env: Environment):
        self.set_path_env(env)

        env.set("APPDIR_LIBRARY_PATH", self._get_appdir_library_paths())

        env.set("LIBC_LIBRARY_PATH", self._get_libc_library_paths())

        glibc_path = self.get_glibc_path()
        glibc_version = self.guess_libc_version(glibc_path)
        env.set("APPDIR_LIBC_VERSION", glibc_version)

        self._patch_executables_interpreter(env.get("APPIMAGE_UUID"))
        env.set("SYSTEM_INTERP", list(self.interpreters.keys()))

    def set_path_env(self, app_run):
        bin_paths = sorted(self._get_bin_paths())
        bin_paths.append("$PATH")
        app_run.set("PATH", bin_paths)

    def _get_appdir_library_paths(self):
        paths = self.finder.find_dirs_containing(
            pattern="*.so*",
            file_checks=[Finder.is_file, Finder.is_elf_shared_lib],
            excluded_patterns=[
                "*/opt/libc*",
                "*/qt5/plugins*",
                "*/perl*",
                "*/perl-base*",
            ],
        )

        return [path.__str__() for path in paths]

    def _get_libc_library_paths(self):
        paths = self.finder.find_dirs_containing(
            pattern="*/opt/libc/*.so*",
            file_checks=[Finder.is_file, Finder.is_elf_shared_lib],
        )
        return [path.__str__() for path in paths]

    def _load_ld_conf_file(self, file):
        paths = set()
        with open(file, "r") as fin:
            for line in fin.readlines():
                if line.startswith("/"):
                    paths.add(line.strip())
        return paths

    @staticmethod
    def guess_libc_version(loader_path):
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
        binaries = self.finder.find(
            pattern="*",
            check_true=[
                Finder.is_file,
                Finder.is_executable,
                Finder.is_elf,
                Finder.is_dynamically_linked_executable,
            ],
        )
        for bin in binaries:
            self._set_interpreter(bin, uuid)

    def _set_interpreter(self, file, uuid):
        try:
            patchelf_command = PatchElf()
            patchelf_command.log_stderr = False
            patchelf_command.log_stdout = False

            original_interpreter = patchelf_command.get_interpreter(file)
            if original_interpreter.startswith("/tmp/appimage-"):
                # skip, the binary has been patched already
                return

            apprun_interpreter = self._gen_interpreter_link_path(
                original_interpreter, uuid
            )
            if original_interpreter and original_interpreter != apprun_interpreter:
                # only include interpreters from standard paths
                if original_interpreter.startswith("/lib"):
                    self.interpreters[original_interpreter] = apprun_interpreter
                logging.info(
                    "Replacing PT_INTERP on: %s" % os.path.relpath(file, self.app_dir)
                )
                logging.debug(
                    '\t"%s"  => "%s"' % (original_interpreter, apprun_interpreter)
                )
                patchelf_command.set_interpreter(file, apprun_interpreter)
        except PatchElfError:
            pass

    @staticmethod
    def _gen_interpreter_link_path(real_interpreter, uuid):
        return "/tmp/appimage-%s-%s" % (uuid, os.path.basename(real_interpreter))

    def _get_bin_paths(self):
        paths = self.finder.find_dirs_containing(
            pattern="*",
            file_checks=[Finder.is_file, Finder.is_executable],
            excluded_patterns=["*/opt/libc*"],
        )
        return [path.__str__() for path in paths]
