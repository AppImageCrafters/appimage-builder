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
from pathlib import Path

from .base_helper import BaseHelper
from ..environment import GlobalEnvironment


class Python(BaseHelper):
    def configure(self, env: GlobalEnvironment):
        python_path = self.app_dir_cache.find_one("*/bin/python?", attrs=["is_bin"])
        if python_path:
            python_home = Path(python_path).parent.parent
            env.set("PYTHONHOME", str(python_home))
