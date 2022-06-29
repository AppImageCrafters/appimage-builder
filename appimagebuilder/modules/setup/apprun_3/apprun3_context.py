#  Copyright  2022 Alexis Lopez Zubieta
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

from appimagebuilder.context import Context
from appimagebuilder.modules.setup.apprun_3.app_dir_info import AppDir
from appimagebuilder.modules.setup.apprun_binaries_resolver import AppRunBinariesResolver


class AppRun3Context:
    build_context: Context = None
    binaries_resolver: AppRunBinariesResolver = None
    app_dir: AppDir = None

    modules_dir: pathlib.Path = None
    debug: bool = False

    main_arch: str = None
    architectures = set()
    environment_variables = set()

    # files matching the given pattern will not be modified by setup helpers
    files_to_preserve = set()

    def __init__(self, build_context: Context):
        self.build_context = build_context
        self.modules_dir = build_context.app_dir / "opt"
        self.debug = build_context.recipe.AppDir.runtime.debug() or False

        # init AppRun binaries resolver
        apprun_version = build_context.recipe.AppDir.runtime.version() or "v3.0.0"
        build_context.build_dir / "AppRun" / apprun_version
        self.binaries_resolver = AppRunBinariesResolver(apprun_version, self.debug, build_context.build_dir)

        self.app_info = build_context.app_info

        # information gathered during the setup process
        self.bundle_archs = set(build_context.recipe.AppDir.runtime.architecture())

        self.app_dir = AppDir(build_context.app_dir)
