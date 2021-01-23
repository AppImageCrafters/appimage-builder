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
import os
import uuid
from pathlib import Path

from appimagebuilder.app_dir.file_info_cache import FileInfoCache
from . import helpers
from .apprun_binaries_resolver import AppRunBinariesResolver
from .environment import GlobalEnvironment, Environment
from .executables import BinaryExecutable, InterpretedExecutable
from .executables_scanner import ExecutablesScanner
from .executables_wrapper import ExecutablesWrapper
from ...common.file_test import read_elf_arch
from ...recipe import Recipe


class RuntimeGeneratorError(RuntimeError):
    pass


class RuntimeGenerator:
    def __init__(self, recipe: Recipe, file_info_cache: FileInfoCache):
        self.appdir_path = Path(recipe.get_item("AppDir/path")).absolute()
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

        scanner = ExecutablesScanner(self.appdir_path, self.file_info_cache)
        resolver = AppRunBinariesResolver(self.apprun_version, self.apprun_debug)
        wrapper = ExecutablesWrapper(self.appdir_path, resolver, runtime_env)

        executables = self._find_executables(scanner)
        self._find_embed_archs(executables)

        # Wrap interpreted executables
        for executable in executables:
            if isinstance(executable, InterpretedExecutable):
                wrapper.wrap(executable)

        self._deploy_appdir_apprun(wrapper, runtime_env)

    def _find_embed_archs(self, executables):
        embed_archs = []
        for executable in executables:
            if isinstance(executable, BinaryExecutable):
                embed_archs.append(executable.arch)
        if not embed_archs:
            raise RuntimeError("Unable to determine the bundle architecture")

    def _find_executables(self, scanner):
        executables = []
        files = self.file_info_cache.find("*", ["is_exec", "is_file"])
        for file in files:
            new_executables = scanner.scan_file(file)
            executables.extend(new_executables)

        return executables

    def _configure_runtime_environment(self):
        global_env = GlobalEnvironment()
        global_env.set("APPIMAGE_UUID", str(uuid.uuid4()))
        global_env.set(
            "XDG_DATA_DIRS",
            [
                "$APPDIR/usr/local/share",
                "$APPDIR/usr/share",
                "$XDG_DATA_DIRS",
            ],
        )
        global_env.set("XDG_CONFIG_DIRS", ["$APPDIR/etc/xdg", "$XDG_CONFIG_DIRS"])
        global_env.set("LD_PRELOAD", "libapprun_hooks.so")

        self._run_configuration_helpers(global_env)
        for k, v in self.user_env.items():
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
            inst = helper(self.appdir_path, self.file_info_cache)
            inst.configure(global_env)

    def _deploy_appdir_apprun(self, wrapper, global_environment):
        self._write_appdir_env(global_environment, wrapper)
        arch = read_elf_arch(self.appdir_path / self.main_exec)
        wrapper.deploy_apprun(arch, self.appdir_path / "AppRun")
        wrapper.deploy_hooks_lib(arch)

    def _write_appdir_env(self, global_environment, wrapper):
        apprun_env = {
            "APPDIR": "$ORIGIN/",
            "APPIMAGE_UUID": None,
            "EXEC_PATH": "$APPDIR/" + self.main_exec,
            "EXEC_ARGS": self.main_exec_args,
        }
        # set defaults
        for k, v in global_environment.items():
            apprun_env[k] = v
        # override defaults with the user_env
        for k, v in self.user_env.items():
            apprun_env[k] = v
        # drop empty keys
        for k in list(apprun_env.keys()):
            if not apprun_env[k]:
                del apprun_env[k]

        with open(self.appdir_path / ".env", "w") as f:
            result = Environment.serialize(apprun_env)
            result = result.replace(str(self.appdir_path), "$APPDIR")
            f.write(result)
