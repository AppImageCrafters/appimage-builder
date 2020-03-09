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
        linker_dir = os.path.join(self.app_dir, 'lib')
        logging.debug("Looking linker binary at: %s\n" % linker_dir)

        binary_path = self._find_loader_by_name()
        binary_path = self._make_path_relative_to_app_dir(binary_path)

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

        linker_path = self.get_loader_path()
        appimage_id = app_run.env['APPIMAGE_UUID']

        interpreter = '/tmp/appimage_ld.so.%s' % appimage_id

        app_run.env['INTERPRETER'] = interpreter
        app_run.env['INTERPRETER_RELATIVE'] = '$APPDIR/%s' % linker_path
        self._set_executables_interpreter(interpreter)

    def _make_path_relative_to_app_dir(self, binary_path):
        binary_path = os.path.realpath(binary_path)
        binary_path = os.path.abspath(binary_path)
        abs_app_dir_path = os.path.abspath(self.app_dir) + '/'
        binary_path = binary_path.replace(abs_app_dir_path, '')

        return binary_path

    def _find_loader_by_name(self) -> str:
        for file in self.app_dir_files:
            if self._is_linker_file(file):
                return file

        raise DynamicLoaderError('Unable to find \'ld.so\' in the AppDir')

    @staticmethod
    def _is_linker_file(file):
        return fnmatch.fnmatch(file, '*/ld-*.so*')

    def _set_executables_interpreter(self, interpreter):
        for file in self.app_dir_files:
            if not os.path.islink(file):
                self._set_interpreter(file, interpreter)

    @staticmethod
    def _set_interpreter(file, interpreter):
        try:
            patchelf_command = PatchElf()
            patchelf_command.log_stderr = False
            if patchelf_command.get_interpreter(file):
                logging.info('Setting interpreter to: %s' % file)
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

    @staticmethod
    def _is_shared_lib(path):
        file_name = os.path.basename(path)
        return file_name.endswith('.so') or '.so.' in file_name

    def _wrap_executable(self, path):
        name = os.path.basename(path)
        dir_path = os.path.dirname(path)

        if self._is_wrapped_already(dir_path, name) or self._should_not_be_wrapped(path):
            return

        wrapped_name = '.%s' % name
        relative_dir_path = dir_path.replace(self.app_dir, '').strip()
        relative_path = os.path.join(relative_dir_path, wrapped_name)
        logging.info('Wrapping executable: %s' % path.replace(self.app_dir, ''))

        shutil.move(path, os.path.join(dir_path, wrapped_name))
        with open(path, 'w') as f:
            f.write('#!/bin/bash\n')
            f.write('# Generated by appimage-builder\n\n')
            f.write('$INTERPRETER --library-path "$LIBRARY_PATH" "$APPDIR%s" "$@"\n\n' % relative_path)

        self._set_execution_permissions(path)

    @staticmethod
    def _is_wrapped_already(dir_path, name):
        return name.startswith('.') and os.path.exists(os.path.join(dir_path, name[1:]))

    def _set_execution_permissions(self, path):
        os.chmod(path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH)

    def _should_not_be_wrapped(self, path):
        return fnmatch.fnmatch(path, '*/libc-*.so')
