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
import shutil
import subprocess

from appimagebuilder.utils.finder import Finder
from .base_helper import BaseHelper
from ..environment import Environment


class GLib(BaseHelper):
    def configure(self, env: Environment, preserve_files):
        self._configure_gio_modules(env)
        self._configure_schemas(env)
        self._configure_girepository(env)

    def _configure_gio_modules(self, env):
        gio_modules_dir = self.finder.find_one("**/gio/modules")
        if gio_modules_dir:
            env.set("GIO_MODULE_DIR", str(gio_modules_dir))

    def _configure_girepository(self, env):
        path = self.finder.find_one("*/girepository-1.0", [Finder.is_dir])
        if path:
            env.set("GI_TYPELIB_PATH", path)

    def _configure_schemas(self, env):
        path = self.finder.find_one("*/glib-2.0/schemas", [Finder.is_dir])
        if path:
            bin_path = shutil.which("glib-compile-schemas")
            if not bin_path:
                raise RuntimeError("Missing 'glib-compile-schemas' executable")

            subprocess.run([bin_path, path])
            env.set("GSETTINGS_SCHEMA_DIR", path)
