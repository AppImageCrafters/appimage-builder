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

from appimagebuilder.utils.finder import Finder
from .base_helper import BaseHelper
from ..environment import Environment


class LibGL(BaseHelper):
    def configure(self, env: Environment, preserve_files):
        dri_path = self.finder.find_one("*/dri/*.so", [Finder.is_file, Finder.is_elf])
        if dri_path:
            env.set("LIBGL_DRIVERS_PATH", dri_path.parent)
