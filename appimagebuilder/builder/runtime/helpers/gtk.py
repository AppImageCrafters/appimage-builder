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
from pathlib import Path

from appimagebuilder.common.finder import Finder
from .base_helper import BaseHelper
from ..environment import Environment


class Gtk(BaseHelper):
    """
    Helper for making Gtk based applications portable
    Reference: https://developer.gnome.org/gtk3/stable/gtk-running.html
    """

    def configure(self, env: Environment):
        libgtk_path = self.finder.find_one(
            "*/libgtk-*", [Finder.is_file, Finder.is_elf_shared_lib]
        )
        if libgtk_path:
            prefix = Path(libgtk_path).parent.parent
            env.set("GTK_EXE_PREFIX", str(prefix))
            env.set("GTK_DATA_PREFIX", str(prefix))
