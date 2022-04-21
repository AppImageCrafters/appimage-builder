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

import configparser
import pathlib
import shlex

from appimagebuilder.context import AppInfo


class DesktopEntryParser:
    def parse(self, entry_path) -> AppInfo:
        entry_path = pathlib.Path(entry_path)

        app_info = AppInfo()

        parser = configparser.RawConfigParser()
        parser.read(entry_path)

        app_info.id = entry_path.stem
        app_info.name = parser["Desktop Entry"]["Name"]
        app_info.icon = parser["Desktop Entry"]["Icon"]

        # process exec
        exec_str = parser["Desktop Entry"]["Exec"].strip()

        # convert desktop file exec args to bash notation
        exec_str = exec_str.replace("%f", "$1")
        exec_str = exec_str.replace("%F", "$@")
        exec_str = exec_str.replace("%U", "$@")
        exec_str = exec_str.replace("%u", "$1")

        exec_str_parts = shlex.split(exec_str)
        app_info.exec = exec_str_parts[0]

        if len(exec_str_parts) > 1:
            app_info.exec_args = " ".join(exec_str_parts[1:])
        else:
            app_info.exec_args = ""

        return app_info
