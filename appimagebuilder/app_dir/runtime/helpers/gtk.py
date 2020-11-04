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
import subprocess

from .base_helper import BaseHelper


class Gtk(BaseHelper):
    """
    Helper for making Gtk based applications portable
    Reference: https://developer.gnome.org/gtk3/stable/gtk-running.html
    """

    def configure(self, app_run):
        libgtk_path = self.app_dir_cache.find("*/libgtk-*")
        if libgtk_path:
            app_run.env["GTK_EXE_PREFIX"] = "$APPDIR"
            app_run.env["GTK_DATA_PREFIX"] = "$APPDIR"
