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
import os
import shutil
import stat
import subprocess
import uuid
import logging
from urllib import request


class AppRunError(RuntimeError):
    pass


class WrapperAppRun:
    env = {
        'APPIMAGE_UUID': None,
        'SYSTEM_INTERP': None,
        'APPDIR_INTERP': None,
        'RUNTIME_INTERP': None,
        'XDG_DATA_DIRS': '${APPDIR}/usr/local/share:${APPDIR}/usr/share:${XDG_DATA_DIRS}',
        'XDG_CONFIG_DIRS': '$APPDIR/etc/xdg:$XDG_CONFIG_DIRS',
        'PATH': '$APPDIR/bin:$APPDIR/usr/bin:$PATH',
    }

    sections = {}

    def __init__(self, app_dir, exec_path, exec_args='$@'):
        self.app_dir = app_dir
        self.env['APPIMAGE_UUID'] = str(uuid.uuid4())
        self.env['EXEC_PATH'] = "$APPDIR/%s" % exec_path
        self.env['EXEC_ARGS'] = exec_args

    def deploy(self):
        self._download_wrapper_binaries()
        self._download_apprun_binaries()

        libc_signature = self._get_embed_libc_signature()

        apprun_path = self._find_apprun_path(libc_signature)
        shutil.copy(apprun_path, os.path.join(self.app_dir, "AppRun"))
        self._set_execution_permissions(os.path.join(self.app_dir, "AppRun"))

        wrapper_path = self._find_wrapper_path(libc_signature)
        lib_paths = self.env['APPDIR_LIBRARY_PATH'].replace("$APPDIR", self.app_dir)
        lib_paths = lib_paths.replace("${APPDIR}", self.app_dir)
        lib_paths = lib_paths.split(":")
        os.makedirs(os.path.join(self.app_dir, lib_paths[0]), exist_ok=True)
        shutil.copy(wrapper_path, os.path.join(self.app_dir, lib_paths[0], "libapprun_hooks.so"))

        self.env['LD_PRELOAD'] = 'libapprun_hooks.so'
        self._generate_env_file()

    def _get_embed_libc_signature(self):
        libc_path = self._find_libc_path()
        if not libc_path:
            raise AppRunError('Unable to locate libc at: %s' % self.app_dir)

        return self._get_elf_arch_signature(libc_path)

    def _generate_env_file(self):
        with open(os.path.join(self.app_dir, '.env'), 'w') as f:
            for k, v in self.env.items():
                f.write("%s=%s\n" % (k, v))

    def _get_elf_arch_signature(self, file):
        proc_env = os.environ.copy()
        proc_env['LC_ALL'] = 'C'
        proc = subprocess.run(['file', '-b', file], stdout=subprocess.PIPE, env=proc_env)
        output = proc.stdout.decode('utf-8')
        parts = output.split(',')
        signature = ','.join(parts[1:2])
        signature = signature.replace('shared object', '')
        signature = signature.replace('executable', '')
        return signature

    def _download_wrapper_binaries(self):
        self.wrapper_binaries = []
        for arch in ['amd64', 'arm64', 'armhf', 'i386']:
            file_path = os.path.join(os.curdir, 'appimage-builder-cache', 'libapprun_hooks-%s.so' % arch)
            url = 'https://github.com/AppImageCrafters/AppRun/releases/download/v1.1.0/libapprun_hooks-%s.so' % arch

            if not os.path.exists(file_path):
                logging.info('Downloading libapprun_hooks binary: %s' % url)
                request.urlretrieve(url, file_path)

            self.wrapper_binaries.append(file_path)

    def _download_apprun_binaries(self):
        self.apprun_binaries = []
        for arch in ['amd64', 'arm64', 'armhf', 'i386']:
            file_path = os.path.join(os.curdir, 'appimage-builder-cache', 'AppRun-%s' % arch)
            url = 'https://github.com/AppImageCrafters/AppRun/releases/download/v1.1.0/AppRun-%s' % arch

            if not os.path.exists(file_path):
                logging.info('Downloading AppRun binary: %s' % url)
                request.urlretrieve(url, file_path)

            self.apprun_binaries.append(file_path)

    def _find_libc_path(self):
        for base_path, dirs, files in os.walk(self.app_dir):
            for file in files:
                abs_path = os.path.join(base_path, file)
                if fnmatch.fnmatch(abs_path, '*/libc-*.so'):
                    return abs_path

    def _find_wrapper_path(self, libc_signature):
        for wrapper in self.wrapper_binaries:
            signature = self._get_elf_arch_signature(wrapper)
            if libc_signature == signature:
                return wrapper

        raise AppRunError('Unable to find a wrapper for: %s' % libc_signature)

    def _find_apprun_path(self, libc_signature):
        for apprun in self.apprun_binaries:
            signature = self._get_elf_arch_signature(apprun)
            if libc_signature == signature:
                return apprun

        raise AppRunError('Unable to find a AppRun for: %s' % libc_signature)

    def _set_execution_permissions(self, path):
        os.chmod(path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH)
