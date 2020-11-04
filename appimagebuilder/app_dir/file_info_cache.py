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

from appimagebuilder.commands.patchelf import PatchElf, PatchElfError
from appimagebuilder.common.file_test import is_elf


class FileInfoCache:
    def __init__(self, path):
        self.path = os.path.realpath(path)
        self.cache = {}
        self.logger = logging.getLogger("AppDir")

    def update(self):
        self.logger.info("Updating files cache")
        for root, dirs, files in os.walk(self.path):
            for dir_name in dirs:
                abs_path = os.path.join(root, dir_name)
                self.cache[abs_path] = {
                    "path": abs_path,
                    "mtime": os.path.getmtime(abs_path),
                    "is_dir": True,
                }

            for file_name in files:
                abs_path = os.path.join(root, file_name)
                if os.path.islink(abs_path):
                    self.cache[abs_path] = {
                        "path": abs_path,
                        "is_link": True,
                    }
                else:
                    if abs_path not in self.cache:
                        self.cache[abs_path] = self.inspect_file(abs_path)
                    else:
                        os.path.getmtime(abs_path)
                        if os.path.getmtime(abs_path) != self.cache[abs_path]["mtime"]:
                            self.cache[abs_path] = self.inspect_file(abs_path)

                    logging.debug(self.cache[abs_path])

    def find(self, pattern, attrs=None):
        """
        Find files matching the patter and the attributes (attrs)

        Allowed attrs:
        - 'is_file'
        - 'is_link'
        - 'is_dir'
        - 'is_elf'
        - 'is_lib'
        - 'is_bin'
        """
        if attrs is None:
            attrs = []

        results = []
        for file in self.cache.keys():
            if fnmatch.fnmatch(file, pattern):
                file_info = self.cache[file]
                if self.match_file_info_attrs(file_info, attrs):
                    results.append(file)

        return results

    @staticmethod
    def match_file_info_attrs(file_info, attrs):
        for attr in attrs:
            if attr not in file_info:
                return False

            if not file_info[attr]:
                return False

        return True

    def inspect_file(self, path):
        file_info = {"path": path, "is_file": True}

        mtime = os.path.getmtime(path)
        # don't inspect files if they haven't been modified since last update
        if path in self.cache:
            file_info = self.cache[path]
            if mtime == file_info["mtime"]:
                return file_info

        file_info["mtime"] = mtime

        if is_elf(path):
            file_info["is_elf"] = True
            try:
                patchelf = PatchElf()
                patchelf.logger.level = logging.WARNING
                patchelf.log_stderr = False
                file_info["pt_needed"] = patchelf.get_needed(path)

                # an exception is raised if the elf has no PT_INTERP section
                file_info["pt_interp"] = patchelf.get_interpreter(path)
            except PatchElfError:
                pass

            if os.access(path, os.X_OK):
                file_info["is_bin"] = True
            else:
                file_info["is_lib"] = True

        return file_info
