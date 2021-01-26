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
from ..environment import GlobalEnvironment


class FontConfig(BaseHelper):
    def __init__(self, app_dir, app_dir_cache):
        super().__init__(app_dir, app_dir_cache)
        self.priority = 0

    def configure(self, global_env: GlobalEnvironment):
        fonts_dir = self.app_dir_cache.find_one("*/share/fonts", ["is_dir"])
        if fonts_dir:
            font_conf_path = os.path.join(self.app_dir, "etc/fonts/fonts.conf")

            global_env.set("FONTCONFIG_FILE", font_conf_path)
            global_env.set("FONTCONFIG_SYSROOT", self.app_dir)

            self._generate_fonts_conf(font_conf_path)

    def _generate_fonts_conf(self, font_conf_path):
        env = os.environ.copy()
        env["FONTCONFIG_FILE"] = font_conf_path.__str__()
        _proc = subprocess.run(
            ["fc-cache", "-s", "-v", "-f", "--sysroot=%s" % self.app_dir], env=env
        )
        if _proc.returncode:
            raise RuntimeError(
                '"%s" execution failed with code %s' % (_proc.args, _proc.returncode)
            )
