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
        apprun_path = self._find_apprun_path()

        shutil.copy(apprun_path, os.path.join(self.app_dir, "AppRun"))

        shutil.copy(wrapper_path, os.path.join(self.app_dir, "libapprun_hooks.so"))
        app_run.env['LD_PRELOAD'] = '${APPDIR}/"libapprun_hooks.so"'




