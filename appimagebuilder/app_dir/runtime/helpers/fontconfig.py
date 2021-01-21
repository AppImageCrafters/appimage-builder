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

from .base_helper import BaseHelper
from ..environment import GlobalEnvironment


class FontConfig(BaseHelper):
    fonts_conf_template = """<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
    <dir prefix="relative">{appdir_fonts_dir}</dir>
    <include ignore_missing="yes" prefix="xdg">fontconfig/fonts.conf</include>
    <include ignore_missing="yes">conf.d</include>
    <include ignore_missing="yes">local.conf</include>
</fontconfig>
"""

    def __init__(self, app_dir, app_dir_cache):
        super().__init__(app_dir, app_dir_cache)
        self.priority = 0

    def configure(self, global_env: GlobalEnvironment):

        fonts_dir = self.app_dir_cache.find_one("*/share/fonts", ["is_dir"])
        if fonts_dir:
            font_conf_path = os.path.join(self.app_dir, "etc/fonts/fonts.conf")

            global_env.set("FONTCONFIG_FILE", font_conf_path)
            # global_env.set("FONTCONFIG_PATH", fontconfig_path)
            # global_env.set("FONTCONFIG_SYSROOT", self.app_dir)

            self._generate_fonts_conf(fonts_dir, font_conf_path)

    def _generate_fonts_conf(self, fonts_dir, font_conf_path):
        font_conf_dir = os.path.dirname(font_conf_path)
        rel_fonts_dir = os.path.relpath(fonts_dir, font_conf_dir)
        fonts_conf_data = self.fonts_conf_template.format(
            appdir_fonts_dir=rel_fonts_dir
        )

        os.makedirs(os.path.dirname(font_conf_path), exist_ok=True)
        with open(font_conf_path, "w") as file:
            file.write(fonts_conf_data)
