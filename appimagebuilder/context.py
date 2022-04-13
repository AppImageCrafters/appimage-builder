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

import roam


class AppInfo:
    id: str
    name: str
    icon: str
    version: str
    exec: str
    exec_args: str

    def __init__(
        self,
        id: str = None,
        name: str = None,
        icon: str = None,
        version: str = None,
        exec: str = None,
        exec_args: str = None,
    ):
        self.id = id
        self.name = name
        self.icon = icon
        self.version = version
        self.exec = exec
        self.exec_args = exec_args


class BundleInfo:
    """Application information"""

    app_dir: pathlib.Path

    app_info: AppInfo

    # update string to be attached into
    update_string: str

    # appimage runtime arch
    runtime_arch: str

    # sign key to be used
    sign_key: str

    # resulting file name
    file_name: str

    def __init__(
        self,
        app_dir: pathlib.Path = None,
        app_info: AppInfo = None,
        update_string: str = None,
        runtime_arch: str = None,
        sign_key: str = None,
        file_name: str = None,
    ):
        self.app_dir = app_dir
        self.app_info = AppInfo() if not app_info else app_info

        self.update_string = update_string
        self.runtime_arch = runtime_arch
        self.sign_key = sign_key
        self.file_name = file_name


class Context:
    """Define a context for commands"""

    app_info: AppInfo
    bundle_info: BundleInfo

    recipe: roam.Roamer
    recipe_path: pathlib.Path
    app_dir: pathlib.Path
    build_dir: pathlib.Path

    # Used by command to register their actions
    record: dict

    def __init__(
        self,
        recipe: roam.Roamer,
        recipe_path: pathlib.Path,
        app_info,
        bundle_info,
        app_dir: pathlib.Path,
        build_dir: pathlib.Path,
    ):
        self.recipe = recipe
        self.recipe_path = recipe_path
        self.app_info = app_info
        self.bundle_info = bundle_info
        self.app_dir = app_dir.absolute()
        self.build_dir = build_dir.absolute()
        self.record = {}
