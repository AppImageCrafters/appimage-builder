#  Copyright  2021 Alexis Lopez Zubieta
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

import pathlib

from appimagebuilder.app_info import AppInfo


class BundleInfo:
    """Application information"""

    app_dir: pathlib.Path

    app_info: AppInfo

    # update string to be attached into
    update_string: str

    # appimage runtime arch
    runtime_arch: str

    def __init__(
        self,
        app_dir: pathlib.Path = None,
        app_info: AppInfo = None,
        update_string: str = None,
        runtime_arch: str = None,
    ):
        self.app_dir = app_dir
        self.app_info = AppInfo() if not app_info else app_info

        self.update_string = update_string
        self.runtime_arch = runtime_arch
