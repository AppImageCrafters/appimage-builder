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

from .base_helper import BaseHelper


class GdkPixbuf(BaseHelper):

    def configure(self, app_run):
        dri_path = self._get_gdk_pixbud_loaders_path()
        if dri_path:
            app_run.env['GDK_PIXBUF_MODULEDIR'] = '${APPDIR}/%s' % dri_path

    def _get_gdk_pixbud_loaders_path(self):
        return self._get_glob_relative_sub_dir_path('*/usr/*/gdk-pixbuf-2.0/*/loaders/*')
