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
import fnmatch
import logging
import os
import pathlib
import shlex
import shutil
import tarfile

import lief
import packaging.version

from appimagebuilder.context import Context
from appimagebuilder.modules.setup import file_matching_patterns, apprun_utils
from appimagebuilder.modules.setup.apprun_3.app_dir_info import AppDir, AppDirFileInfo
from appimagebuilder.modules.setup.apprun_3.helpers.glibc_module import AppRun3GLibCSetupHelper
from appimagebuilder.modules.setup.apprun_binaries_resolver import AppRunBinariesResolver
from appimagebuilder.utils.finder import Finder


class AppRunV3Setup:
    """
    AppRun v3 setup module

    Configures an AppDir to use the AppRun v3 runtime format.
    """

    def __init__(self, context: Context, finder: Finder):
        self.context = context
        self.finder = finder
        self._apprun_version = self.context.recipe.AppDir.runtime.version() or "v3.0.0"
        self._apprun_cache_dir = context.build_dir / "AppRun" / self._apprun_version
        self._apprun_debug = self.context.recipe.AppDir.runtime.debug() or False
        self._apprun_modules_dir = self.context.app_dir / "opt"

        self._apprun_binaries_resolver = AppRunBinariesResolver(self._apprun_version, self._apprun_debug,
                                                                self.context.build_dir)

        # information gathered during the setup process
        self._bundle_archs = set(self.context.recipe.AppDir.runtime.architecture())

        # use first architecture from list as default
        self._main_arch = None

        self._binary_interpreters = set()

        self._app_dir_info = AppDir(self.context.app_dir)

    def setup(self):
        """Configures the AppDir to use the AppRun v3 runtime format."""

        # scan AppDir contents
        self._app_dir_info.scan_files()

        # resolve main architecture to know which AppRun binaries should be used later
        self._main_arch = self._get_main_arch()

        self._setup_apprun_modules()

        self._bundle_archs.update(self._app_dir_info.architectures)

        # patch scripts shebang to use embed interpreters
        self._patch_scripts_shebang()

        # deploy AppRun v3 runtime
        self._deploy_librapprun_hooks_so()
        self._deploy_apprun_bin()
        self._deploy_apprun_config()

    def _find_dirs_containing_libraries(self):
        library_paths = set()
        appdir_path_str = self._app_dir_info.base_path.__str__()

        for file in self._app_dir_info.files.values():
            # check if the binary is a library
            if file.soname and not self._is_file_in_a_module(file):
                # record the library dir path for later use in the apprun config generation
                library_dir = file.path.parent
                library_paths.add(library_dir)

        return library_paths

    def _is_file_in_a_module(self, file: AppDirFileInfo):
        """Checks if a file belongs to a module"""

        path_str = file.path.__str__()
        return path_str.startswith(self._apprun_modules_dir.__str__())

    def _deploy_librapprun_hooks_so(self):
        for arch in self._bundle_archs:
            self._deploy_libapprun_hooks_so(arch.name)

    def _deploy_apprun_bin(self):
        """Deploys the AppRun binary for the main architecture"""

        apprun_bin_path = self._apprun_binaries_resolver.resolve_executable(self._main_arch)
        apprun_bin_target_path = self.context.app_dir / "AppRun"

        shutil.copy(apprun_bin_path, apprun_bin_target_path)

        # make binary executable
        apprun_bin_target_path.chmod(0o755)

    def _deploy_libapprun_hooks_so(self, arch):
        """Deploys the libapprun_hooks.so for a given architecture"""

        libapprun_so_path = self._apprun_binaries_resolver.resolve_hooks_library(arch)

        libapprun_so_target_dir = self._find_libapprun_hooks_so_target_dir(arch)

        # provide a target dir if none was found
        if not libapprun_so_target_dir:
            libapprun_so_target_dir = self.context.app_dir / "lib" / arch
            libapprun_so_target_dir.mkdir(parents=True, exist_ok=True)

        # copy the libapprun_hooks.so to the target dir
        libapprun_so_target_path = libapprun_so_target_dir / "libapprun_hooks.so"
        shutil.copy(libapprun_so_path, libapprun_so_target_path)

    def _find_libapprun_hooks_so_target_dir(self, arch):
        """Finds a suitable directory for the libapprun_hooks.so"""

        base_dirs = [
            self.context.app_dir / "lib",
            self.context.app_dir / "lib64",
            self.context.app_dir / "usr/lib",
            self.context.app_dir / "usr/lib64",
        ]
        # find dedicated folder for the architecture
        for base_dir in base_dirs:
            for entry in base_dir.iterdir():
                if entry.is_dir() and arch in entry.name:
                    return entry

        return None

    def _deploy_apprun_config(self):
        """Deploys the AppRun config file"""

        exec_line = ["$APPDIR/" + self.context.app_info.exec]
        if self.context.app_info.exec_args:
            exec_line.extend(self.context.app_info.exec_args)
        else:
            exec_line.append("$@")

        library_paths = self._find_dirs_containing_libraries()
        library_paths = [self._replace_app_dir_in_path(path) for path in library_paths]

        path_env = self._find_dirs_containing_executable_files()
        path_env = [self._replace_app_dir_in_path(path) for path in path_env]

        config = {
            "version": "1.0",
            "runtime": {
                "exec": exec_line,
                "library_paths": library_paths,
                "linkers": list(self._binary_interpreters),
                "environment": {
                    "PATH": ":".join(path_env),
                    "LD_PRELOAD": "libapprun_hooks.so:$LD_PRELOAD:",
                },
            },
        }

        if len(list(self._apprun_modules_dir.iterdir())) > 0:
            config["runtime"]["modules_dir"] = (
                    "$APPDIR/"
                    + self._apprun_modules_dir.relative_to(self.context.app_dir).__str__()
            )

        # write the config file
        apprun_config_path = self.context.app_dir / "AppRun.config"
        apprun_utils.write_config_file(config, apprun_config_path)

    def _replace_appdir_path_by_environment_variable_in_paths(self, paths: [str]):
        """Replaces the appdir path by the $APPDIR environment variable in a list of paths"""

        patched_paths = []
        for path in paths:
            appdir_path_str = self.context.app_dir.__str__()
            if appdir_path_str in path:
                new_path = path.replace(appdir_path_str, "$APPDIR")
                patched_paths.append(new_path)

        return sorted(patched_paths)

    def _move_files_to_module_dir(self, files, target_module_dir):
        """Moves files to a module directory"""

        new_file_paths = []
        for entry in files:
            relative_path = entry.relative_to(self.context.app_dir)
            target_path = target_module_dir / relative_path

            # ensure target dir exists
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # move file to target dir
            shutil.move(entry, target_path)
            new_file_paths.append(target_path)

        return new_file_paths

    def _match_files_in_dir(self, patterns):
        """Matches files in a directory"""

        matching_files = []

        # iterate over all files in the app dir
        search_queue = [self.context.app_dir]
        while search_queue:
            current_dir = search_queue.pop()

            for entry in current_dir.iterdir():
                if entry.is_dir():
                    search_queue.append(entry)

                elif entry.is_file():
                    full_path = entry.__str__()
                    if any(fnmatch.fnmatch(full_path, pattern) for pattern in patterns):
                        matching_files.append(entry)

        return matching_files

    def _setup_apprun_modules(self):
        """Sets up the AppRun modules"""

        glibc_helper = AppRun3GLibCSetupHelper(self.context, self._app_dir_info, self._apprun_modules_dir,
                                               self._apprun_binaries_resolver, self._main_arch)
        glibc_helper.setup()

        self._setup_glibstdcpp_module()

    def _setup_glibstdcpp_module(self):
        self._glibstdcpp_module_files = self._match_files_in_dir(
            file_matching_patterns.glibstdcpp
        )

        if self._glibstdcpp_module_files:
            glibc_module_dir = self._apprun_modules_dir / "glibstdcpp"
            glibc_module_dir.mkdir(parents=True, exist_ok=True)

            self._glibstdcpp_module_files = self._move_files_to_module_dir(
                file_matching_patterns.glibstdcpp, glibc_module_dir
            )

    def _get_main_arch(self):
        """Resolves the main architecture"""

        # check if there are user defined archictectures and use first one as main arch
        if self._bundle_archs:
            return next(iter(self._bundle_archs))

        # get executable archictecture
        executable_path = self.context.app_dir / self.context.app_info.exec
        arch = self._get_executable_architecture(executable_path)

        return arch

    def _get_executable_architecture(self, executable_path):
        """Resolves the executable architecture"""

        error_message_prefix = "Could not resolve executable architecture"
        arch = None
        iterations_count = 0

        current_executable_path = executable_path

        # follow interpreter links until we find a non-link, or we reach the max number of iterations
        while iterations_count < 5 and not arch:
            if not os.path.exists(current_executable_path):
                raise Exception(
                    f"{error_message_prefix}, Could not find executable {current_executable_path} in AppDir"
                )

            binary = lief.parse(current_executable_path.__str__())
            if binary:
                arch = binary.header.machine_type.name
            else:
                # try read shebang
                shebang = apprun_utils.read_shebang(current_executable_path)
                if shebang:
                    rel_interpreter_path = shebang[0].lstrip("/")
                    current_executable_path = (
                            self.context.app_dir / rel_interpreter_path
                    )
                else:
                    raise Exception(
                        f"{error_message_prefix}, not elf or script executable: {current_executable_path}"
                    )

        if not arch:
            raise Exception(
                f"{error_message_prefix}, max iterations reached for: {executable_path}"
            )

        return arch

    def _patch_scripts_shebang(self):
        """Patches the scripts shebang"""

        # patch scripts shebang
        search_queue = [self.context.app_dir]
        while search_queue:
            current_dir = search_queue.pop()

            for entry in current_dir.iterdir():
                if entry.is_dir():
                    search_queue.append(entry)

                elif entry.is_file() and not entry.is_symlink():
                    # patch file shebang
                    self._patch_script_shebang(entry)

    def _patch_script_shebang(self, entry):
        """Patches a script shebang"""

        with open(entry.__str__(), "rb+") as f:
            # assume that the shebang is not longer than 1024 bytes
            chunk = f.read(1024)
            if chunk[0:2] == b"#!":
                chunk = apprun_utils.remove_left_slashes_on_shebang(chunk)
                # check if script interpreter is embed in the AppDir
                interpreter_path = shlex.split(chunk[2:].decode("utf-8"))[0]
                embed_interpreter_path = self.context.app_dir / interpreter_path
                if embed_interpreter_path.exists():
                    # write back the modified chunk
                    f.seek(0)
                    f.write(chunk)
                    logging.info("Patched script shebang: %s", entry.__str__())
                else:
                    logging.warning("Script interpreter not found in AppDir: %s", interpreter_path)

    def _find_dirs_containing_executable_files(self):
        """Finds the dirs containing executable files"""

        executable_dirs = set()
        for file in self._app_dir_info.files.values():
            if file.is_executable and not self._is_file_in_a_module(file):
                dir_path = file.path.parent.__str__()
                executable_dirs.add(dir_path)

        return executable_dirs

    def _replace_app_dir_in_path(self, path):
        """Replaces the app dir in a path"""

        path_str = str(path)
        return path_str.replace(self.context.app_dir.__str__(), "$APPDIR")
