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
import os
import re
import subprocess

from .base_helper import BaseHelper
from ..environment import Environment


class Gtk(BaseHelper):
    """
    Helper for making Gtk based applications portable
    Reference: https://developer.gnome.org/gtk3/stable/gtk-running.html
    """

    def configure(self, env: Environment, preserve_files):
        prefix = self.app_dir / "usr"
        env.set("GTK_EXE_PREFIX", str(prefix))
        env.set("GTK_DATA_PREFIX", str(prefix))

        gtk_path = [
            str(path)
            for path in self.finder.find("lib/**/gtk-?.0", [self.finder.is_dir])
        ]
        env.set("GTK_PATH", gtk_path)

        for path in self.finder.find("usr/share/icons/*", [self.finder.is_dir]):
            subprocess.run(["gtk-update-icon-cache", str(path)])
