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

from AppImageBuilder.app_dir.runtimes.classic.helpers.base_helper import BaseHelper
from AppImageBuilder.commands.patchelf import PatchElf


class DynamicLoaderError(RuntimeError):
    pass


class DynamicLoader(BaseHelper):
    def __init__(self, app_dir, app_dir_files):
        super().__init__(app_dir, app_dir_files)

        self.priority = 100
        self.patch_elf = PatchElf()
        self.patch_elf.logger.level = logging.WARNING

    def get_binary_path(self) -> str:
        binary_path = self._find_binary_by_name()
        binary_path = self._resolve_symlink(binary_path)
        binary_path = self._make_path_relative_to_app_dir(binary_path)

        return binary_path

    def configure(self, app_run):
        linker_path = self.get_binary_path()
        library_dirs_paths = self.get_library_dirs_paths()
        app_run.env['LINKER_PATH'] = '$APPDIR/%s' % linker_path
        app_run.env['LD_LIBRARY_DIRS'] = library_dirs_paths

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

    def _find_binary_by_name(self) -> str:
        path = self._get_glob_relative_file_path('*/lib/ld-*.so*')
        if not path:
            path = self._get_glob_relative_file_path('*/lib64/ld-*.so*')

        return os.path.join(self.app_dir, path)

    def get_library_dirs_paths(self):
        rel_lib_dirs = set()
        rel_lib_dirs.add(self._get_glob_relative_sub_dir_path('*/libtalloc.so*'))
        rel_lib_dirs.add(self._get_glob_relative_sub_dir_path('*/libc.so*'))

        prefixed_rel_lib_dirs = ['$APPDIR/%s' % path for path in rel_lib_dirs]

        return ';'.join(prefixed_rel_lib_dirs)

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
