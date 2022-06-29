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

from .base_helper import AppRun3Helper


class AppRun3GLib(AppRun3Helper):
    def run(self):
        self._configure_gio_modules()
        self._configure_schemas()
        self._configure_girepository()

    def _configure_gio_modules(self):
        gio_module = self.context.app_dir.find_one(["**/gio/modules/*"])
        if gio_module:
            self.context.runtime_env["GIO_MODULE_DIR"] = str(gio_module.path.parent)

    def _configure_girepository(self):
        path = self.context.app_dir.find_one(["*/girepository-1.0/*"])
        if path:
            self.context.runtime_env["GI_TYPELIB_PATH"] = str(path.path.parent)

    def _configure_schemas(self):
        schema_file = self.context.app_dir.find_one(["*/glib-2.0/schemas/*"])
        if schema_file:
            bin_path = shutil.which("glib-compile-schemas")
            if not bin_path:
                raise RuntimeError("Missing 'glib-compile-schemas' executable")

            subprocess.run([bin_path, schema_file.path.parent])
            self.context.runtime_env["GSETTINGS_SCHEMA_DIR"] = str(schema_file.path.parent)
