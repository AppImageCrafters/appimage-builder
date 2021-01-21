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

import logging
import uuid
from pathlib import Path

from appimagebuilder.app_dir.file_info_cache import FileInfoCache
from . import helpers
from .apprun_binaries_resolver import AppRunBinariesResolver
from .environment import GlobalEnvironment
from .executables import BinaryExecutable
from .executables_scanner import ExecutablesScanner
from .executables_wrapper import ExecutablesWrapper
from ...recipe import Recipe


class RuntimeGeneratorError(RuntimeError):
    pass


class RuntimeGenerator:
    def __init__(self, recipe: Recipe, file_info_cache: FileInfoCache):
        self.app_dir = Path(recipe.get_item("AppDir/path")).absolute()
        self.main_exec = recipe.get_item("AppDir/app_info/exec")
        self.main_exec_args = recipe.get_item("AppDir/app_info/exec_args", "$@")
        self.apprun_version = recipe.get_item("AppDir/runtime/version", "v1.2.3")
        self.apprun_debug = recipe.get_item("AppDir/runtime/debug", False)
        self.user_env = recipe.get_item("AppDir/runtime/env", {})
        self.path_mappings = recipe.get_item("AppDir/runtime/path_mappings", [])

        self.file_info_cache = file_info_cache

    def generate(self):
        self.file_info_cache.update()
        runtime_env = self._configure_runtime_environment()

        scanner = ExecutablesScanner(self.app_dir, self.file_info_cache)
        executables = scanner.scan_file(str(self.app_dir / self.main_exec))
        executables[0].args = self.main_exec_args

        embed_archs = []
        for executable in executables:
            if isinstance(executable, BinaryExecutable):
                embed_archs.append(executable.arch)

        if not embed_archs:
            raise RuntimeError("Unable to determine the bundle architecture")

        resolver = AppRunBinariesResolver(self.apprun_version, self.apprun_debug)
        wrapper = ExecutablesWrapper(self.app_dir, resolver, runtime_env)

        for executable in executables:
            wrapper.wrap(executable)

        apprun_path = self.app_dir / "AppRun"
        apprun_path.symlink_to(self.main_exec)

    def _configure_runtime_environment(self):
        global_env = GlobalEnvironment()
        global_env.set("APPIMAGE_UUID", str(uuid.uuid4()))

        self._run_configuration_helpers(global_env)
        for k, v in self.user_env:
            if k in global_env:
                logging.info("Overriding runtime environment %s" % k)

            global_env.set(k, v)

        global_env.set("PATH_MAPPINGS", self.path_mappings)

        return global_env

    def _run_configuration_helpers(self, global_env):
        execution_list = [
            helpers.FontConfig,
            helpers.GdkPixbuf,
            helpers.GLibSchemas,
            helpers.GStreamer,
            helpers.Gtk,
            helpers.Interpreter,
            helpers.Java,
            helpers.LibGL,
            helpers.OpenSSL,
            helpers.Python,
            helpers.Qt,
        ]

        for helper in execution_list:
            inst = helper(self.app_dir, self.file_info_cache)
            inst.configure(global_env)
