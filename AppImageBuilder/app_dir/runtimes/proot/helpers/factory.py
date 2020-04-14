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

from AppImageBuilder.app_dir.runtimes.classic.helpers.base_helper import BaseHelper
from AppImageBuilder.app_dir.runtimes.classic.helpers.factory import HelperFactoryError

from .dynamic_loader import DynamicLoader
from .gdk_pixbuf import GdkPixbuf
from .proot import PRoot
from .glib_schemas import GLibSchemas


class PRootHelperFactory:
    def __init__(self, app_dir, app_dir_files):
        self.app_dir = app_dir
        self.app_dir_files = app_dir_files

        self.helpers = {
            'loader': DynamicLoader,
            'proot': PRoot,
            'glib_schemas': GLibSchemas,
            'gdk_pixbuf': GdkPixbuf,
        }

    def get(self, id) -> BaseHelper:
        if id in self.helpers:
            obj = self.helpers[id](self.app_dir, self.app_dir_files)
            return obj
        else:
            raise HelperFactoryError('%s: unknown helper id' % id)

    def list(self):
        return self.helpers.keys()
