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

from appimagebuilder.common.finder import Finder
from . import helpers
from .apprun_binaries_resolver import AppRunBinariesResolver
from .environment import Environment
from .executables import BinaryExecutable, InterpretedExecutable
from .executables_scanner import ExecutablesScanner
from .executables_wrapper import ExecutablesWrapper
from ...common.elf import get_arch
from ...recipe import Recipe


class RuntimeGeneratorError(RuntimeError):
    pass


class RuntimeGenerator:
    def __init__(self, recipe: Recipe, finder: Finder):
        self.appdir_path = Path(recipe.get_item("AppDir/path")).absolute()
        self.main_exec = recipe.get_item("AppDir/app_info/exec")
        self.main_exec_args = recipe.get_item("AppDir/app_info/exec_args", "$@")
        self.apprun_version = recipe.get_item("AppDir/runtime/version", "v1.2.4")
        self.apprun_debug = recipe.get_item("AppDir/runtime/debug", False)
        user_env_input = recipe.get_item("AppDir/runtime/env", {})
        self.user_env = self.parse_env_input(user_env_input)
        self.path_mappings = recipe.get_item("AppDir/runtime/path_mappings", [])

        self.finder = finder

    def generate(self):
        runtime_env = self._configure_runtime_environment()

        scanner = ExecutablesScanner(self.appdir_path, self.finder)
        resolver = AppRunBinariesResolver(self.apprun_version, self.apprun_debug)
        wrapper = ExecutablesWrapper(self.appdir_path, resolver, runtime_env)

        executables = self._find_executables(scanner)
        self._find_embed_archs(executables)

        self._wrap_interpreted_executables(executables, runtime_env, wrapper)

        self._deploy_appdir_apprun(wrapper, runtime_env)

    def _wrap_interpreted_executables(self, executables, runtime_env, wrapper):
        interpreted_executables = [
            executable
            for executable in executables
            if isinstance(executable, InterpretedExecutable)
        ]

        if interpreted_executables:
            env_path = self.finder.find_one(
                "env", [Finder.is_file, Finder.is_executable]
            )
            if env_path:
                runtime_env.set("EXPORTED_BINARIES", env_path)
                for executable in interpreted_executables:
                    wrapper.wrap(executable)
            else:
                logging.warning(
                    "Missing 'env' binary. Embed interpreted executables will not work"
                )
                logging.warning(
                    "To ensure a proper behaviour of interpreted executables it's recommended "
                    "to bundle the 'env' along with the required interpreters."
                )

    def _find_embed_archs(self, executables):
        embed_archs = []
        for executable in executables:
            if isinstance(executable, BinaryExecutable):
                embed_archs.append(executable.arch)
        if not embed_archs:
            raise RuntimeError("Unable to determine the bundle architecture")

    def _find_executables(self, scanner):
        executables = []
        files = self.finder.find("*", [Finder.is_file, Finder.is_executable])
        for file in files:
            new_executables = scanner.scan_file(file)
            executables.extend(new_executables)

        return executables

    def _configure_runtime_environment(self):
        global_env = Environment(
            {
                "APPIMAGE_UUID": str(uuid.uuid4()),
                "XDG_DATA_DIRS": [
                    "$APPDIR/usr/local/share",
                    "$APPDIR/usr/share",
                    "$XDG_DATA_DIRS",
                ],
                "XDG_CONFIG_DIRS": ["$APPDIR/etc/xdg", "$XDG_CONFIG_DIRS"],
                "LD_PRELOAD": "libapprun_hooks.so",
            }
        )

        self._run_configuration_helpers(global_env)
        for k, v in self.user_env.items():
            if k in global_env:
                logging.info("Overriding runtime environment %s" % k)

            global_env.set(k, v)

        global_env.set("PATH_MAPPINGS", self.path_mappings)

        return global_env

    def _run_configuration_helpers(self, global_env):
        execution_list = [
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
            logging.info("Running configuration helper: %s" % helper.__name__)
            inst = helper(self.appdir_path, self.finder)
            inst.configure(global_env)

    def _deploy_appdir_apprun(self, wrapper, global_environment):
        self._write_appdir_env(global_environment)
        arch = get_arch(self.appdir_path / self.main_exec)
        wrapper.deploy_apprun(arch, self.appdir_path / "AppRun")
        wrapper.deploy_hooks_lib(arch)

    def _write_appdir_env(self, global_environment):
        apprun_env = Environment(
            {
                "APPDIR": "$ORIGIN/",
                "APPIMAGE_UUID": None,
                "EXEC_PATH": "$APPDIR/" + self.main_exec,
                "EXEC_ARGS": self.main_exec_args,
            }
        )

        apprun_env.merge(global_environment)
        apprun_env.merge(self.user_env)
        apprun_env.drop_empty_keys()

        with open(self.appdir_path / ".env", "w") as f:
            result = apprun_env.serialize()
            result = result.replace(str(self.appdir_path), "$APPDIR")
            f.write(result)

    def parse_env_input(self, user_env_input):
        env = dict()
        for k, v in user_env_input.items():
            if isinstance(v, str):
                v = v.replace("$APPDIR", self.appdir_path.__str__())
                v = v.replace("${APPDIR}", self.appdir_path.__str__())

                if (
                    k == "PATH"
                    or k == "APPDIR_LIBRARY_PATH"
                    or k == "LIBC_LIBRARY_PATH"
                ):
                    v = v.split(":")

            env[k] = v

        return env
