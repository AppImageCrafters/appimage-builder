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

from AppImageBuilder.app_dir.runtime.helpers.base_helper import BaseHelper


class PRootError(RuntimeError):
    pass


class PRoot(BaseHelper):
    def configure(self, app_run):
        path = self._get_proot_path()
        if path:
            app_run.env['PROOT_PATH'] = '${APPDIR}/%s' % path
            app_run.env['PROOT_NO_SECCOMP'] = 1
        else:
            raise PRootError('Unable to find proot binary')

    def _get_proot_path(self):
        return self._get_glob_relative_file_path('*/bin/proot')
