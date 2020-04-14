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
from .dynamic_loader import DynamicLoader
from .base_helper import BaseHelper
from .fontconfig import FontConfig
from .gstreamer import GStreamer
from .java import Java
from .libgl import LibGL
from .openssl import OpenSSL
from .qt import Qt
from .gdk_pixbuf import GdkPixbuf
from .glib_schemas import GLibSchemas


class HelperFactoryError(RuntimeError):
    pass


class HelperFactory:
    def __init__(self, app_dir, app_dir_files):
        self.app_dir = app_dir
        self.app_dir_files = app_dir_files

        self.helpers = {
            'loader': DynamicLoader,
            'fontconfig': FontConfig,
            'openssl': OpenSSL,
            'qt': Qt,
            'libgl': LibGL,
            'gstreamer': GStreamer,
            'gdk_pixbuf': GdkPixbuf,
            'glib_schemas': GLibSchemas,
            'java': Java,
        }

    def get(self, id) -> BaseHelper:
        if id in self.helpers:
            obj = self.helpers[id](self.app_dir, self.app_dir_files)
            return obj
        else:
            raise HelperFactoryError('%s: unknown helper id' % id)

    def list(self):
        return self.helpers.keys()
