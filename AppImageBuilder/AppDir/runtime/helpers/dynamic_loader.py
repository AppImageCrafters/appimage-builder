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

from .base_helper import BaseHelper


class DynamicLoader(BaseHelper):
    def __init__(self, app_dir, app_dir_files):
        super().__init__(app_dir, app_dir_files)

        self.priority = 100

    def get_binary_path(self) -> str:
        linker_dir = os.path.join(self.app_dir, 'lib')
        logging.debug("Looking linker binary at: %s\n" % linker_dir)

        binary_path = self._find_binary_by_name(linker_dir)
        binary_path = self._resolve_symlink(binary_path)
        binary_path = self._make_path_relative_to_app_dir(binary_path)

        return binary_path

    def _make_path_relative_to_app_dir(self, binary_path):
        binary_path = os.path.abspath(binary_path)
        abs_app_dir_path = os.path.abspath(self.app_dir) + '/'
        binary_path = binary_path.replace(abs_app_dir_path, '')

        return binary_path

    def _resolve_symlink(self, binary_path):
        if os.path.islink((binary_path)):
            link_target = os.readlink(binary_path)

            if link_target.startswith('/'):
                binary_path = os.path.join(self.app_dir, link_target)
            else:
                dir = os.path.dirname(binary_path)
                binary_path = os.path.join(dir, link_target)

        return binary_path

    def _find_binary_by_name(self, linker_dir) -> str:
        for file in self.app_dir_files:
            if self._is_a_linker_binary(file, linker_dir):
                return file

    @staticmethod
    def _is_a_linker_binary(file, linker_dir):
        file_name = os.path.basename(file)
        return file.startswith(linker_dir) and file_name.startswith('ld-linux') and '.so' in file_name

    def configure(self, app_run):
        linker_path = self.get_binary_path()

        app_run.env['LINKER_PATH'] = os.path.join('$APPDIR', linker_path)
        app_run.env['LD_LIBRARY_DIRS'] = ';'.join(self._get_ld_library_dirs())

    def _get_ld_library_dirs(self):
        relative_elf_dir_paths = self._list_lib_dirs()
        return {"${APPDIR}/%s" % dir for dir in relative_elf_dir_paths}

    def _list_lib_dirs(self):
        elf_file_paths = self._list_libs()

        elf_dirs_paths = {os.path.dirname(file) for file in elf_file_paths}

        relative_elf_dir_paths = {dir.replace(self.app_dir, '').lstrip('/') for dir in elf_dirs_paths}

        return relative_elf_dir_paths

    def _list_libs(self):
        library_files = []
        for full_path in self.app_dir_files:
            if self._is_shared_lib(full_path):
                library_files.append(full_path)

        return library_files

    @staticmethod
    def _is_shared_lib(path):
        file_name = os.path.basename(path)
        return file_name.endswith('.so') or '.so.' in file_name
