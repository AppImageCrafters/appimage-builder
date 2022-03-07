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
from functools import reduce

from packaging import version

from appimagebuilder.gateways.patchelf import PatchElf, PatchElfError
from appimagebuilder.utils.finder import Finder
from .base_helper import BaseHelper
from ..environment import Environment


class InterpreterHandlerError(RuntimeError):
    pass


class LibC(BaseHelper):
    def __init__(self, app_dir, finder):
        super().__init__(app_dir, finder)

        self.priority = 100
        self.patch_elf = PatchElf()
        self.patch_elf.logger.level = logging.WARNING
        self.interpreters = set()

    def get_glibc_path(self) -> str:
        path = self.finder.find_one("*/libc.so.*", [Finder.is_elf_shared_lib])
        if not path:
            raise InterpreterHandlerError("Unable to find libc.so")

        logging.info("Libc found at: %s" % os.path.relpath(path, self.app_dir))
        return path

    def configure(self, env: Environment):
        try:
            self._patch_executables_interpreter()
            env.set("APPRUN_LD_PATHS", list(self.interpreters))
            env.set("LIBC_LIBRARY_PATH", self._get_libc_library_paths())
        except InterpreterHandlerError as err:
            logging.warning("%s" % err)
            logging.warning(
                "The resulting bundle will not be backward compatible as libc is not present"
            )

    def _get_libc_library_paths(self):
        paths = self.finder.find_dirs_containing(
            pattern="*/runtime/compat/*.so*",
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

    def _patch_executables_interpreter(self):
        binaries = self.finder.find(
            pattern="*",
            check_true=[
                Finder.is_file,
                Finder.is_executable,
                Finder.is_elf,
                Finder.is_dynamically_linked_executable,
            ],
        )
        for bin_path in binaries:
            self._make_interpreter_path_relative(bin_path)

    def _make_interpreter_path_relative(self, bin_path):
        try:
            patchelf_command = PatchElf()
            patchelf_command.log_stderr = False
            patchelf_command.log_stdout = False

            interpreter_path = patchelf_command.get_interpreter(bin_path)
            if interpreter_path.startswith("/"):
                rel_path = interpreter_path.lstrip("/")
                patchelf_command.set_interpreter(bin_path, rel_path)
                self.interpreters.add(rel_path)
        except PatchElfError:
            pass
