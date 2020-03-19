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
import shutil
import stat

from AppImageBuilder.commands.file import File
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

    def get_loader_path(self) -> str:
        binary_path = self._find_loader_by_name()
        binary_path = os.path.realpath(binary_path)
        binary_path = os.path.relpath(binary_path, self.app_dir)

        logging.info("Loader found at: %s" % binary_path)
        return binary_path

    def configure(self, app_run):
        library_paths = self._get_library_paths()
        app_run.env['APPDIR_LIBRARY_PATH'] = ':'.join(['$APPDIR%s' % path for path in library_paths])

        partitions_path = os.path.join(self.app_dir, 'opt')
        for nane in os.listdir(partitions_path):
            if os.path.isdir(os.path.join(partitions_path, nane)):
                partition_library_path = ['opt/%s%s' % (nane, path) for path in library_paths]
                app_run.env['%s_LIBRARY_PATH' % nane.upper()] = ':'.join(
                    ['$APPDIR/%s' % path for path in partition_library_path])

        loader_path = self.get_loader_path()
        app_run.env['INTERPRETER_RELATIVE'] = '$APPDIR/%s' % loader_path

        interpreter = '/tmp/appimage_ld.so.%s' % app_run.env['APPIMAGE_UUID']
        app_run.env['INTERPRETER'] = interpreter
        self._set_executables_interpreter(interpreter)

    def _find_loader_by_name(self) -> str:
        for file in self.app_dir_files:
            if self._is_linker_file(file):
                binary_path = os.path.realpath(file)
                return binary_path

        raise DynamicLoaderError('Unable to find \'ld.so\' in the AppDir')

    @staticmethod
    def _is_linker_file(file):
        return fnmatch.fnmatch(file, '*/ld-*.so*')

    def _set_executables_interpreter(self, interpreter):
        for root, dirs, files in os.walk(self.app_dir):
            for file_name in files:
                path = os.path.join(root, file_name)
                if not os.path.islink(path) and self.is_elf_file(path):
                    self._set_interpreter(path, interpreter)

    def _set_interpreter(self, file, interpreter):
        try:
            patchelf_command = PatchElf()
            patchelf_command.log_stderr = False
            if patchelf_command.get_interpreter(file):
                logging.info('Setting interpreter to: %s' % os.path.relpath(file, self.app_dir))
                patchelf_command.set_interpreter(file, interpreter)
        except PatchElfError:
            pass

    def _get_library_paths(self):
        paths = set()
        for file in self.app_dir_files:
            if fnmatch.fnmatch(file, '*/etc/ld.so.conf.d/*.conf') or fnmatch.fnmatch(file, '*/etc/ld.so.conf'):
                new_paths = self._load_ld_conf_file(file)
                paths = paths.union(new_paths)

        return paths

    def _load_ld_conf_file(self, file):
        paths = set()
        with open(file, 'r') as fin:
            for line in fin.readlines():
                if line.startswith('/'):
                    paths.add(line.strip())
        return paths

    def _set_execution_permissions(self, path):
        os.chmod(path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH)

    @staticmethod
    def is_elf_file(path):
        with open(path, "rb") as f:
            bits = f.read(4)
            if bits == b'\x7fELF':
                return True

        return False
