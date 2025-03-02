#  Copyright  2022 Alexis Lopez Zubieta
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
from typing import Union

import lief

from appimagebuilder.modules.setup import apprun_utils


class AppDirFileInfo:
    """
    File information required by AppRun setup
    """

    path: pathlib.Path
    is_executable: bool = False
    is_elf: bool = False
    shebang: [str] = None
    interpreter: str = None
    machine_type: str = None
    soname: str = None

    def __init__(self, path):
        self.path = pathlib.Path(path)


class AppDir:
    """Holds the information of the files contained in the AppDir"""

    files: {pathlib.Path: AppDirFileInfo} = dict()

    def __init__(self, app_dir_path: pathlib.Path):
        self.path = pathlib.Path(app_dir_path)

        # file information aggregations
        self.architectures = set()
        self.binary_interpreters = set()
        self.script_interpreters = set()

    def scan_files(self):
        """Scans the files in the AppDir"""

        # disable lief's logging to not pollute the output
        lief.logging.disable()

        # iterate over the files in the AppDir
        concurrent_dir = self.path
        explore_queue = []
        while concurrent_dir:
            for entry in concurrent_dir.iterdir():
                if entry.is_dir():
                    explore_queue.append(entry)
                else:
                    file_info = self.read_file_info(entry)
                    self._agregate_file_info(file_info)
                    self.files[entry] = file_info

            concurrent_dir = explore_queue.pop() if explore_queue else None

    @staticmethod
    def read_file_info(entry: pathlib.Path):
        file_info = AppDirFileInfo(entry)

        if entry.is_file():
            binary = lief.parse(entry.__str__())

            file_info.path = entry

            # check if file is executable
            file_info.is_executable = os.access(entry, os.X_OK)
            file_info.shebang = apprun_utils.read_shebang(entry)

            # check if file is an ELF binary
            file_info.is_elf = isinstance(binary, lief.ELF.Binary)
            if file_info.is_elf:
                file_info.interpreter = binary.interpreter
                file_info.machine_type = binary.header.machine_type
                soname = binary.get(lief.ELF.DynamicEntry.TAG.SONAME)
                # store only the string representation of the soname
                if soname:
                    file_info.soname = soname.name

        return file_info

    def _agregate_file_info(self, file_info: AppDirFileInfo):
        """Aggregates the file info to ease access"""

        if file_info.machine_type:
            self.architectures.add(file_info.machine_type)

        if file_info.interpreter:
            self.binary_interpreters.add(file_info.interpreter)

        if file_info.shebang:
            self.script_interpreters.update(file_info.shebang)

    def find(self, patterns: [str]) -> [AppDirFileInfo]:
        """Finds the files from the cache matching the patterns"""

        matching_files = []
        for path, info in self.files.items():
            path_str = path.__str__()
            if any(fnmatch.fnmatch(path_str, pattern) for pattern in patterns):
                matching_files.append(info)

        return matching_files

    def find_one(self, patterns: [str]) -> Union[AppDirFileInfo, None]:
        """Finds the first file from the cache matching the patterns"""

        for info in self.files.values():
            path_str = info.path.__str__()
            if any(fnmatch.fnmatch(path_str, pattern) for pattern in patterns):
                return info

        return None

    def move_files(self, file_list: [AppDirFileInfo], dest_dir):
        """Moves the files inside the AppDir"""

        missing_entries = []
        for entry in file_list:
            source_path = entry.path
            relative_path = source_path.relative_to(self.path)
            target_path = dest_dir / relative_path

            # ensure target dir exists
            target_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                # move file to target dir
                source_path.rename(target_path)
                entry.path = target_path

                # update file info map
                self.files.pop(source_path)
                self.files[target_path] = entry
            except FileNotFoundError:
                missing_entries.append(entry)
                logging.warning(f"File not found: {source_path}")

        for entry in missing_entries:
            file_list.remove(entry)
