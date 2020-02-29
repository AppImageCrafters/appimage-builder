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
import shutil
import subprocess

from urllib import request

from .base_helper import BaseHelper


class WrapperError(RuntimeError):
    pass


class Wrapper(BaseHelper):

    def configure(self, app_run):
        wrapper_path = self._find_wrapper_path()
        shutil.copy(wrapper_path, os.path.join(self.app_dir, os.path.basename(wrapper_path)))

        app_run.env['LD_PRELOAD'] = '${APPDIR}/%s' % os.path.basename(wrapper_path)

    def _download_wrappers(self):
        self.wrappers = []
        for arch in ['amd64', 'arm64', 'armhf', 'i386']:
            file_path = os.path.join(os.curdir, 'appimage-builder-cache', 'libappimage_exec_wrapper-%s.so' % arch)
            url = 'https://github.com/AppImageCrafters/appimage-exec-wrapper/releases/download/continuous/libappimage_exec_wrapper-%s.so' % arch

            if not os.path.exists(file_path):
                logging.info('Downloading exec wrapper: %s' % url)
                request.urlretrieve(url, file_path)

            self.wrappers.append(file_path)

    def _find_libc_path(self):
        relative_path = self._get_glob_relative_file_path('*/libc-*.so')
        return os.path.join(self.app_dir, relative_path)

    def _find_wrapper_path(self):
        self._download_wrappers()

        libc_path = self._find_libc_path()
        if not libc_path:
            raise WrapperError('Unable to locate libc at: %s' % self.app_dir)

        libc_signature = self._get_shared_lib_signature(libc_path)
        for wrapper in self.wrappers:
            signature = self._get_shared_lib_signature(wrapper)
            if libc_signature == signature:
                return wrapper

        raise WrapperError('Unable to find a wrapper for: %s' % libc_signature)

    def _get_shared_lib_signature(self, file):
        proc = subprocess.run(['file', '-b', file], stdout=subprocess.PIPE)
        output = proc.stdout.decode('utf-8')
        parts = output.split(',')
        signature = ','.join(parts[:2])
        return signature
