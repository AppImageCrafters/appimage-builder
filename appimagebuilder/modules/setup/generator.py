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
import random
import string
import uuid
from pathlib import Path

from appimagebuilder.utils.finder import Finder
from . import helpers
from .apprun_binaries_resolver import AppRunBinariesResolver
from .environment import Environment
from .executables import BinaryExecutable, InterpretedExecutable
from .executables_scanner import ExecutablesScanner
from .executables_wrapper import ExecutablesWrapper
from appimagebuilder.utils import elf


class RuntimeGeneratorError(RuntimeError):
    pass


class RuntimeGenerator:
    def __init__(self, recipe: {}, finder: Finder):
        self.appdir_path = Path(recipe.AppDir.path()).absolute()
        self.main_exec = recipe.AppDir.app_info.exec()
        self.main_exec_args = recipe.AppDir.app_info.exec_args() or "$@"
        self.apprun_version = recipe.AppDir.runtime.version() or "v1.2.5"
        self.apprun_debug = recipe.AppDir.runtime.debug()
        user_env_input = recipe.AppDir.runtime.env() or {}
        self.user_env = self.parse_env_input(user_env_input)

        self.deploy_hooks = not recipe.AppDir.runtime.no_hooks()
        if not self.deploy_hooks:
            logging.warning("Runtime hooks will not be deployed")

        self.path_mappings = recipe.AppDir.runtime.path_mappings()
        if self.path_mappings and not self.deploy_hooks:
            logging.error("Hooks required when setting path mappings")
            raise RuntimeError("Path Mappings set without hooks")

        self.finder = finder

    def generate(self):
        runtime_env = self._configure_runtime_environment()

        scanner = ExecutablesScanner(self.appdir_path, self.finder)
        resolver = AppRunBinariesResolver(self.apprun_version, self.apprun_debug)
        wrapper = ExecutablesWrapper(self.appdir_path, resolver, runtime_env)

        executables = self._find_executables(scanner)
        embed_archs = self._find_embed_archs(executables)
        if self.deploy_hooks:
            self._deploy_appdir_hooks(wrapper, runtime_env, embed_archs)

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
        embed_archs = set()
        for executable in executables:
            if isinstance(executable, BinaryExecutable):
                embed_archs.add(executable.arch)
        if not embed_archs:
            raise RuntimeError("Unable to determine the bundle architecture")

        return embed_archs

    def _find_executables(self, scanner):
        executables = []
        files = self.finder.find("*", [Finder.is_file, Finder.is_executable])
        for file in files:
            new_executables = scanner.scan_file(file)
            executables.extend(new_executables)

        return executables

    def _configure_runtime_environment(self):
        bundle_id = "".join(
            random.SystemRandom().choice(string.ascii_letters + string.digits)
            for _ in range(7)
        )

        global_env = Environment(
            {
                "APPIMAGE_UUID": bundle_id,
                "XDG_DATA_DIRS": [
                    "$APPDIR/usr/local/share",
                    "$APPDIR/usr/share",
                    "$XDG_DATA_DIRS",
                ],
                "XDG_CONFIG_DIRS": ["$APPDIR/etc/xdg", "$XDG_CONFIG_DIRS"],
                "APPDIR_LIBRARY_PATH": self._get_appdir_library_paths(),
                "PATH": [*self._get_bin_paths(), "$PATH"],
            }
        )

        self._run_configuration_helpers(global_env)
        for k, v in self.user_env.items():
            if k in global_env:
                logging.info("Overriding runtime environment %s" % k)

            global_env.set(k, v)

        global_env.set("APPRUN_PATH_MAPPINGS", self.path_mappings)

        return global_env

    def _run_configuration_helpers(self, global_env):
        execution_list = [
            helpers.GdkPixbuf,
            helpers.GLib,
            helpers.GStreamer,
            helpers.Gtk,
            helpers.LibC,
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
        bin_path = self.appdir_path / self.main_exec
        if not elf.has_magic_bytes(bin_path):
            raise RuntimeError(f"Main executable is not an elf executable: {bin_path}")

        main_arch = elf.get_arch(bin_path)
        wrapper.deploy_apprun(main_arch, self.appdir_path / "AppRun")

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

    def _deploy_appdir_hooks(self, wrapper, runtime_env, embed_archs):
        if self.deploy_hooks:
            runtime_env.set("LD_PRELOAD", "libapprun_hooks.so")
            
        for arch in embed_archs:
            path = self.appdir_path / "lib" / arch
            path.mkdir(parents=True, exist_ok=True)
            wrapper.deploy_hooks_lib(arch, path)
            runtime_env.append("APPDIR_LIBRARY_PATH", path.__str__())

    def _get_appdir_library_paths(self):
        paths = self.finder.find_dirs_containing(
            pattern="*.so*",
            file_checks=[Finder.is_file, Finder.is_elf_shared_lib],
            excluded_patterns=[
                "*/opt/libc*",
                "*/qt5/plugins*",
                "*/perl*",
                "*/perl-base*",
                "*/gio/modules",
                "*/gtk-*/modules",
                "*/libgtk-*-0",
            ],
        )

        return [path.__str__() for path in paths]

    def _get_bin_paths(self):
        paths = self.finder.find_dirs_containing(
            pattern="*",
            file_checks=[Finder.is_file, Finder.is_executable],
            excluded_patterns=["*/opt/libc*"],
        )
        return sorted([path.__str__() for path in paths])
