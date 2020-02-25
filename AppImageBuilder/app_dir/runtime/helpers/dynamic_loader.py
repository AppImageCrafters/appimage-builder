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

from AppImageBuilder.commands.patchelf import PatchElf, PatchElfError
from .base_helper import BaseHelper


class DynamicLoaderError(RuntimeError):
    pass


class DynamicLoader(BaseHelper):
    def __init__(self, app_dir, app_dir_files):
        super().__init__(app_dir, app_dir_files)

        self.priority = 100
        self.patch_elf = PatchElf()
        self.patch_elf.logger.level = logging.WARNING

    def get_binary_path(self) -> str:
        linker_dir = os.path.join(self.app_dir, 'lib')
        logging.debug("Looking linker binary at: %s\n" % linker_dir)

        binary_path = self._find_binary_by_name(linker_dir)
        binary_path = self._resolve_symlink(binary_path)
        binary_path = self._make_path_relative_to_app_dir(binary_path)

        return binary_path

    def configure(self, app_run):
        linker_path = self.get_binary_path()
        app_run.env['LINKER_PATH'] = '$APPDIR/%s' % linker_path
        self._set_elf_run_paths(app_run.env['APPIMAGE_UUID'])

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
            if self._is_linker_file(file):
                return file
        raise DynamicLoaderError('Unable to find \'ld.so\' in the AppDir')

    @staticmethod
    def _is_linker_file(file):
        return fnmatch.fnmatch(file, '*/lib/*/ld-*.so*') or fnmatch.fnmatch(file, '*/lib64/ld-*.so*')

    def _set_elf_run_paths(self, appimage_uuid):
        for file in self.app_dir_files:
            if not self._is_linker_file(file) and not os.path.islink(file):
                self._patch_elf(file, appimage_uuid)

    def _list_libs(self):
        library_files = []
        for full_path in self.app_dir_files:
            if self._is_shared_lib(full_path):
                library_files.append(full_path)

        return library_files

    def _patch_elf(self, file, appimage_uuid):
        run_path = None
        interpreter_path = None
        try:
            self.patch_elf.log_stderr = False
            needed_libs = self.patch_elf.get_needed(file)
            if needed_libs:
                link_dirs = self._find_elf_link_dirs(needed_libs)
                logging.info("Setting RUN_PATHS to: %s" % os.path.relpath(file, self.app_dir))
                run_path = self._create_elf_run_path_list(file, link_dirs)

        except PatchElfError:
            pass

        try:
            self.patch_elf.log_stderr = False
            interpreter = self.patch_elf.get_interpreter(file)
            if interpreter:
                interpreter_path = '/tmp/appimage_%s.ld.so' % appimage_uuid
                # https://docs.oracle.com/cd/E19957-01/806-0641/chapter6-71736/index.html
                logging.info("Setting PT_INTERP to: %s" % os.path.relpath(file, self.app_dir))

        except PatchElfError:
            pass

        try:
            if run_path or interpreter_path:
                self.patch_elf.log_stderr = True
                self.patch_elf.set(file, run_path=run_path, interpreter=interpreter_path)
        except PatchElfError:
            pass

    @staticmethod
    def _create_elf_run_path_list(file, link_dirs):
        run_path = set()
        for dir_path in link_dirs:
            rel_path = os.path.relpath(dir_path, os.path.dirname(file))
            if rel_path == '.':
                rel_path = ''

            run_path_entry = '$ORIGIN/%s' % rel_path

            logging.debug("\t%s" % run_path_entry)
            run_path.add(run_path_entry)

        return run_path

    def _find_elf_link_dirs(self, needed):
        lib_dirs = set()
        for entry in needed:
            path = self._get_relative_parent_dir_of(entry)
            if path:
                abs_path = os.path.join(self.app_dir, path)
                lib_dirs.add(abs_path)
        return lib_dirs

    @staticmethod
    def _is_shared_lib(path):
        file_name = os.path.basename(path)
        return file_name.endswith('.so') or '.so.' in file_name
