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
import glob
import logging
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

    def configure(self, env: Environment):
        try:
            exe_prefix = (
                subprocess.check_output(
                    ["pkg-config", "--variable=exec_prefix", "gtk+-3.0"]
                )
                .decode()
                .strip()
            )
            libdir = (
                subprocess.check_output(["pkg-config", "--variable=libdir", "gtk+-3.0"])
                .decode()
                .strip()
            )
            binary_version = (
                subprocess.check_output(
                    ["pkg-config", "--variable=gtk_binary_version", "gtk+-3.0"]
                )
                .decode()
                .strip()
            )

            path = libdir + "/gtk-3.0"
            env.set("GTK_EXE_PREFIX", str(self.app_dir) + exe_prefix)
            env.set("GTK_PATH", str(self.app_dir) + path)
            env.set("GTK_DATA_PREFIX", str(self.app_dir))

            immodules_dir = os.path.join(path, binary_version, "immodules")
            env.set("GTK_IM_MODULE_DIR", str(self.app_dir) + immodules_dir)

            gtk_query_immodules_tool_path = glob.glob(
                "/usr/**/gtk-query-immodules-3.0", recursive=True
            )
            if not gtk_query_immodules_tool_path:
                logging.error("Missing tool: gtk-query-immodules-3.0")
                return

            query_immodules_output = subprocess.check_output(
                [gtk_query_immodules_tool_path[0]]
            ).decode()

            # remove absolute paths from module names
            query_immodules_output = re.sub(
                r"\"(/.*/)(\S+)\"\s*\n", r'"\2"\n', query_immodules_output
            )

            immodules_cache_file = os.path.join(path, binary_version, "immodules.cache")
            with open(str(self.app_dir) + immodules_cache_file, "w") as f:
                f.write(query_immodules_output)

            env.set("GTK_IM_MODULE_FILE", str(self.app_dir) + immodules_cache_file)

        except subprocess.CalledProcessError as err:
            logging.error(err)
