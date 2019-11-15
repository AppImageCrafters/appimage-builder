#  Copyright  2019 Alexis Lopez Zubieta
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
import stat


class AppRunBuilder:
    export_appdir = True
    export_xdg_data_dirs = True
    library_paths = []
    linker_path = None
    hooks = []

    def __init__(self, appdir_path, app_runnable, linker_path):
        self.appdir_path = appdir_path
        self.app_runnable = app_runnable
        self.linker_path = linker_path

        self.apprun_path = os.path.join(self.appdir_path, "AppRun")

    def build(self):
        f = open(self.apprun_path, "w")

        self._write_header(f)

        if self.export_appdir:
            f.write("if [ -z ${APPDIR+x} ]; then\n"
                    "   APPDIR=\"$( cd \"$( dirname \"${BASH_SOURCE[0]}\" )\" >/dev/null 2>&1 && pwd )\"\n"
                    "fi\n")

        if self.export_xdg_data_dirs:
            f.write("export XDG_DATA_DIRS=\"${APPDIR}\"/usr/share/:\"${XDG_DATA_DIRS}\"\n")

        for hook in self.hooks:
            commands = hook.app_run_commands()
            if commands:
                f.write(commands)

        exec_command = "exec \"${APPDIR}/%s\" --inhibit-cache " % self.linker_path

        if self.library_paths:
            exec_command = exec_command + "--library-path \"${APPDIR}/%s\" " % ":${APPDIR}/".join(self.library_paths)

        exec_command = exec_command + "\"${APPDIR}/%s\" $@\n" % self.app_runnable

        f.write(exec_command)

        f.close()

        self._set_permissions()

    def _write_header(self, f):
        f.write("#!/bin/bash\n"
                "#\n"
                "# This file was created by AppImageBuilder\n")

    def _set_permissions(self):
        os.chmod(self.apprun_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH)

    def _find_linker(self):
        linker_path = None
        for root, dirs, files in os.walk(self.appdir_path):
            for filename in files:
                print(os.path.join(root, filename))
                if filename.startswith("ld-linux") and filename.endswith(".so.2"):
                    absolute_path = os.path.join(root, filename)
                    linker_path = os.path.relpath(absolute_path, self.appdir_path)
        return linker_path
