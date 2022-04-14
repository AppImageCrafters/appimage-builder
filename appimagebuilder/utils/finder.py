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

import appimagebuilder.utils.elf
from appimagebuilder.utils import shell


class Finder:
    """
    Provides a simple interface for searching files in a directory.

    Supports performing checks on the files and keeps a cache of the
    results.
    """

    def __init__(self, base_path):
        self.base_path = pathlib.Path(base_path)
        self.cache = {}
        self.logger = logging.getLogger("CachedFinder")

    @staticmethod
    def is_file(path: pathlib.Path):
        return path.is_file()

    @staticmethod
    def is_dir(path: pathlib.Path):
        return path.is_dir()

    @staticmethod
    def is_symlink(path: pathlib.Path):
        return path.is_symlink()

    @staticmethod
    def is_executable(path: pathlib.Path):
        return os.access(path, os.X_OK)

    @staticmethod
    def is_elf(path: pathlib.Path):
        if not path.is_file():
            return False

        try:
            return appimagebuilder.utils.elf.has_magic_bytes(path)
        except RuntimeError:
            return False

    @staticmethod
    def is_elf_shared_lib(path: pathlib.Path):
        try:
            return appimagebuilder.utils.elf.has_soname(path)
        except shell.CommandNotFoundError:
            raise
        except RuntimeError:
            return False

    @staticmethod
    def is_dynamically_linked_executable(path: pathlib.Path):
        try:
            return appimagebuilder.utils.elf.has_start_symbol(path)
        except shell.CommandNotFoundError:
            raise
        except:
            return False

    def find_dirs_containing(
        self,
        pattern="*",
        file_checks: [] = None,
        excluded_patterns=None,
    ):
        if file_checks is None:
            file_checks = []

        if excluded_patterns is None:
            excluded_patterns = []

        for root, _, files in os.walk(self.base_path):
            root_path = pathlib.Path(root)
            if self.match_patterns(root_path, excluded_patterns):
                continue

            for filename in files:
                path = root_path / filename
                if not fnmatch.fnmatch(path, pattern):
                    continue

                if self.check_file(path, file_checks):
                    yield path.parent
                    break

    @staticmethod
    def match_patterns(path, patterns):
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                return True

        return False

    def find_one(self, pattern="*", check_true: [] = None, check_false: [] = None):
        try:
            return next(self.find(pattern, check_true, check_false))
        except StopIteration:
            return None

    def find(self, pattern="*", check_true: [] = None, check_false: [] = None):
        if check_true is None:
            check_true = []

        if check_false is None:
            check_false = []

        check_true_names = [item.__name__ for item in check_true]
        check_false_names = [item.__name__ for item in check_false]
        logging.debug(
            "FIND %s %s %s"
            % (pattern, " ".join(check_true_names), " ".join(check_false_names))
        )

        for path in self.base_path.rglob(pattern):
            if self.check_file(path, check_true, check_false):
                yield path.absolute()

    def check_file(self, path, check_true: [] = None, check_false: [] = None):
        if check_true is None:
            check_true = []

        if check_false is None:
            check_false = []

        for check_function in check_true:
            passed = self._run_check(check_function, path)
            if not passed:
                return False

        for check_function in check_false:
            passed = self._run_check(check_function, path)
            if passed:
                return False

        return True

    def _run_check(self, check_function, path):
        key = (path.__str__(), check_function.__name__)
        if key in self.cache:
            return self.cache[key]
        else:
            passed = check_function(path)
            self.cache[key] = passed
            return passed

    @staticmethod
    def list_does_not_contain_file(file_list: [pathlib.Path], file: pathlib.Path):
        for item in file_list:
            if item == file:
                return False
        return True

    def get_preserve_files(self, preserve_paths: [str]):
        _preserve_files = []
        base_paths = [
            self.base_path,
            self.base_path / "runtime" / "compat",
        ]
        for pattern in preserve_paths:
            for base_path in base_paths:
                for match in base_path.glob(pattern):
                    if match.is_dir():
                        _preserve_files.extend(match.glob("**/*"))
                    else:
                        _preserve_files.append(match)
        return _preserve_files
