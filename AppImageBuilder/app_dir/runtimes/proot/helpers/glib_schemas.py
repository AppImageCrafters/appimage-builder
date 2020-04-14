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
import subprocess

from AppImageBuilder.app_dir.runtimes.classic.helpers.base_helper import BaseHelper


class GLibSchemas(BaseHelper):

    def configure(self, app_run):
        path = self._get_glib_schemas_path()
        if path:
            subprocess.run(['glib-compile-schemas', path], cwd=self.app_dir)

    def _get_glib_schemas_path(self):
        return self._get_glob_relative_sub_dir_path('*/usr/share/glib-2.0/schemas/*')
