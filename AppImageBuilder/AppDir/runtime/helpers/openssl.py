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

from .base_helper import BaseHelper


class OpenSSL(BaseHelper):
    def __init__(self, app_dir, app_dir_files):
        super().__init__(app_dir, app_dir_files)

    def configure(self, app_run):
        engines_dir = self._get_engines_dir()

        if engines_dir:
            app_run.env['OPENSSL_ENGINES'] = engines_dir

    def _get_engines_dir(self):
        return self._get_relative_sub_dir_path('openssl-1.0.0/engines')
