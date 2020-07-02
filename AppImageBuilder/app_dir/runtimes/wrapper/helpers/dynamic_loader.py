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
import re
import stat

from packaging import version
from functools import reduce

from AppImageBuilder.common.file_test import is_elf
from .base_helper import BaseHelper
from AppImageBuilder.commands.patchelf import PatchElf, PatchElfError


class DynamicLoaderError(RuntimeError):
    pass


class DynamicLoader(BaseHelper):
    def __init__(self, app_dir, app_dir_files):
        super().__init__(app_dir, app_dir_files)

        self.priority = 100
        self.patch_elf = PatchElf()
        self.patch_elf.logger.level = logging.WARNING
        self.system_interpreter = None

    def get_loader_path(self) -> str:
        binary_path = self._find_loader_by_name()
        binary_path = os.path.realpath(binary_path)
        binary_path = os.path.relpath(binary_path, self.app_dir)

        logging.info("Loader found at: %s" % binary_path)
        return binary_path

    def get_glibc_path(self) -> str:
        path = self._get_glob_relative_file_path('*/libc.so.*')
        if not path:
            raise DynamicLoaderError('Unable to find libc.so')
        path = os.path.join(self.app_dir, path)
        path = os.path.realpath(path)

        logging.info("Libc found at: %s" % os.path.relpath(path, self.app_dir))
        return path

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
        app_run.env['APPDIR_INTERP'] = '$APPDIR/%s' % loader_path

        glibc_path = self.get_glibc_path()
        glibc_version = self.gess_libc_version(glibc_path)
        app_run.env['APPDIR_LIBC_VERSION'] = glibc_version

        interpreter = '/tmp/appimage-%s-ld-linux.so.2' % app_run.env['APPIMAGE_UUID']
        app_run.env['RUNTIME_INTERP'] = interpreter

        self._set_executables_interpreter(interpreter)
        app_run.env['SYSTEM_INTERP'] = self.system_interpreter

    def _find_loader_by_name(self) -> str:
        for file in self.app_dir_files:
            if self._is_linker_file(file):
                binary_path = os.path.realpath(file)
                return binary_path

        raise DynamicLoaderError('Unable to find \'ld.so\' in the AppDir')

    @staticmethod
    def _is_linker_file(file):
        return fnmatch.fnmatch(file, '*/ld-*.so*')

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

    def gess_libc_version(self, loader_path):
        glib_version_re = re.compile(r'GLIBC_(?P<version>\d+\.\d+\.?\d*)')
        with open(loader_path, 'rb') as f:
            content = str(f.read())
            glibc_version_strings = glib_version_re.findall(content)
            if glibc_version_strings:
                glibc_version_strings = map(version.parse, glibc_version_strings)
                max_glibc_version = reduce((lambda x, y: max(x, y)), glibc_version_strings)
                return str(max_glibc_version)
            else:
                raise DynamicLoaderError('Unable to determine glibc version')

    def _set_executables_interpreter(self, interpreter):
        for root, dirs, files in os.walk(self.app_dir):
            for file_name in files:
                path = os.path.join(root, file_name)
                if not os.path.islink(path) and is_elf(path):
                    self._set_interpreter(path, interpreter)

    def _set_interpreter(self, file, interpreter):
        try:
            patchelf_command = PatchElf()
            patchelf_command.log_stderr = False
            bin_interpreter = patchelf_command.get_interpreter(file)
            if bin_interpreter and bin_interpreter != interpreter:
                self.system_interpreter = bin_interpreter
                logging.info('Setting interpreter to: %s' % os.path.relpath(file, self.app_dir))
                patchelf_command.set_interpreter(file, interpreter)
        except PatchElfError:
            pass
