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


class InterpreterHandlerError(RuntimeError):
    pass


class Interpreter(BaseHelper):
    def __init__(self, app_dir, app_dir_files):
        super().__init__(app_dir, app_dir_files)

        self.priority = 100
        self.patch_elf = PatchElf()
        self.patch_elf.logger.level = logging.WARNING
        self.interpreters = {}

    def get_glibc_path(self) -> str:
        path = self._get_glob_relative_file_path('*/libc.so.*')
        if not path:
            raise InterpreterHandlerError('Unable to find libc.so')
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

        glibc_path = self.get_glibc_path()
        glibc_version = self.gess_libc_version(glibc_path)
        app_run.env['APPDIR_LIBC_VERSION'] = glibc_version

        self._patch_executables_interpreter(app_run.env['APPIMAGE_UUID'])
        app_run.env['SYSTEM_INTERP'] = ":".join(self.interpreters.keys())


    def _resolve_appdir_interpreters(self):
        appdir_interp = []
        for path in self.interpreters.keys():
            rel_path = self._get_relative_file_path(path)
            if rel_path:
                appdir_interp.append('$APPDIR/%s' % rel_path)
            else:
                raise InterpreterHandlerError('Interpreter not being bundled: %s' % path)
        return appdir_interp

    def _find_loader_by_name(self) -> str:
        for file in self.app_dir_files:
            if self._is_linker_file(file):
                binary_path = os.path.realpath(file)
                return binary_path

        raise InterpreterHandlerError('Unable to find \'ld.so\' in the AppDir')

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
                raise InterpreterHandlerError('Unable to determine glibc version')

    def _patch_executables_interpreter(self, uuid):
        for root, dirs, files in os.walk(self.app_dir):
            for file_name in files:
                path = os.path.join(root, file_name)
                if not os.path.islink(path) and is_elf(path):
                    self._set_interpreter(path, uuid)

    def _set_interpreter(self, file, uuid):
        try:
            patchelf_command = PatchElf()
            patchelf_command.log_stderr = False
            real_interpreter = patchelf_command.get_interpreter(file)
            apprun_interpreter = self._gen_interpreter_link_path(real_interpreter, uuid)
            if real_interpreter and real_interpreter != apprun_interpreter:
                self.interpreters[real_interpreter] = apprun_interpreter
                logging.info('Replacing PT_INTERP on: %s' % os.path.relpath(file, self.app_dir))
                logging.info('\t"%s"  => "%s"' % (real_interpreter, apprun_interpreter))
                patchelf_command.set_interpreter(file, apprun_interpreter)
        except PatchElfError:
            pass

    @staticmethod
    def _gen_interpreter_link_path(real_interpreter, uuid):
        return "/tmp/appimage-%s-%s" % (uuid, os.path.basename(real_interpreter))
