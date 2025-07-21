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

import logging
import os
import pathlib
import shutil
import subprocess

import lief
import packaging

from appimagebuilder.modules.setup import apprun_utils, file_matching_patterns
from appimagebuilder.modules.setup.apprun_3.app_dir_info import AppDirFileInfo
from appimagebuilder.modules.setup.apprun_3.apprun3_context import AppRun3Context
from appimagebuilder.modules.setup.apprun_3.helpers.base_helper import AppRun3Helper
from appimagebuilder.modules.setup.apprun_utils import replace_app_dir_in_path


class AppRun3GLibCSetupHelper(AppRun3Helper):
    """Setups the GLibC module for AppRun 3"""

    def __init__(self, context: AppRun3Context):
        super().__init__(context)

        self._module_dir = self.context.modules_dir / "glibc"
        self._glibc_module_files = []

    def run(self):
        """Configures glibc for AppRun 3"""

        # extract glibc module files
        self._glibc_module_files = self.context.app_dir.find(
            file_matching_patterns.glibc
        )
        if self._glibc_module_files:
            self._module_dir.mkdir(parents=True, exist_ok=True)

            self._patch_binaries_interpreter_path()
            self.context.app_dir.move_files(self._glibc_module_files, self._module_dir)

            # create links to the interpreters paths, so they can be found at runtime
            self._link_binary_interpreter_to_their_default_path()
            self._link_script_interpreters_to_their_path()

            library_paths = self._extract_library_paths_from_glibc_module_files()

            self._deploy_check_glibc_binary()
            self._generate_glibc_module_config(library_paths)

    def _patch_binaries_interpreter_path(self):
        """Patches the binaries interpreter path on the AppDir"""

        for file in self.context.app_dir.files.values():
            if (
                file.interpreter
                and not self._is_file_in_a_module(file)
                and not file.path.is_symlink()
            ):
                binary = lief.parse(file.path.__str__())
                self._patch_binary_interpreter_path(binary, file.path)

    def _patch_binary_interpreter_path(self, binary, path: pathlib.Path):
        """Patch the interpreter of a binary making it relative"""

        interpreter = binary.interpreter
        new_interpreter = interpreter.lstrip("/")

        subprocess.run(
            [
                "patchelf",
                "--set-interpreter",
                new_interpreter,
                path.__str__(),
            ],
            check=True,
        )

    def _extract_library_paths_from_glibc_module_files(self):
        """Extracts library paths from glibc module files"""

        library_paths = set()
        for module_file in self._glibc_module_files:
            if module_file.soname:
                library_paths.add(module_file.path.parent.__str__())

        return library_paths

    def _generate_glibc_module_config(self, library_paths):
        library_paths = [
            replace_app_dir_in_path(self.context.app_dir.path, path)
            for path in library_paths
        ]
        runtime_dir = (
            "$APPDIR/"
            + self._module_dir.relative_to(self.context.app_dir.path).__str__()
        )
        config = {
            "version": "1.0",
            "check": {
                "required_glibc": self._find_bundled_glibc_version(),
            },
            "module": {
                "runtime_dir": runtime_dir,
                "library_paths": library_paths,
            },
        }

        # write the config file
        glibc_module_config_path = self._module_dir / "config"
        apprun_utils.write_config_file(config, glibc_module_config_path)

    def _find_bundled_glibc_version(self):
        """Finds the bundled glibc version"""

        # find versioned glibc filename
        for file in self._glibc_module_files:
            file_path = file.path
            if file_path.match("libc-*.so"):
                glibc_version = file_path.stem.split("-")[1]
                return glibc_version

        # find unversioned glibc file
        unversioned_glibc_file_path = None
        for file in self._glibc_module_files:
            if file.soname == "libc.so.6":
                unversioned_glibc_file_path = file.path

        if not unversioned_glibc_file_path:
            raise Exception("Could not find glibc library in module files")

        # extract major version from binary `GLIBC_` symbols
        major_version = packaging.version.parse("0.0.0")
        binary = lief.parse(unversioned_glibc_file_path.__str__())
        for symbol_version in binary.symbols_version:
            # read symbol version name
            version_name = (
                symbol_version.symbol_version_auxiliary.name
                if symbol_version.symbol_version_auxiliary
                else None
            )

            # compare with current major version and update if necessary
            if version_name and version_name.startswith("GLIBC_"):
                version_value = version_name.split("_")[1]
                parsed_version = packaging.version.parse(version_value)
                if parsed_version > major_version:
                    major_version = parsed_version

        if major_version == packaging.version.parse("0.0.0"):
            raise Exception("Could not find glibc library in module files")

        return major_version.__str__()

    def _link_binary_interpreter_to_their_default_path(self):
        """Links the binary interpreter to their default path"""

        sys_root = pathlib.Path("/")
        for binary_interpreter in self.context.app_dir.binary_interpreters:
            binary_interpreter_path = (
                self.context.app_dir.path / binary_interpreter.__str__().strip("/")
            )

            # ensure the binary interpreter dir exists
            binary_interpreter_path.parent.mkdir(parents=True, exist_ok=True)

            binary_interpreter_path.symlink_to(sys_root / binary_interpreter)

    def _link_script_interpreters_to_their_path(self):
        """Links the script interpreters to their path"""

        for interpreter_path in self.context.app_dir.script_interpreters:
            rel_path = pathlib.Path(interpreter_path.strip("/"))
            expected_path = self.context.app_dir.path / rel_path
            if expected_path.exists():
                mirror_path = self._module_dir / rel_path
                rel_mirror_path = os.path.relpath(expected_path, mirror_path.parent)

                mirror_path.parent.mkdir(parents=True, exist_ok=True)
                logging.info("Linking script interpreter: %s", interpreter_path)
                mirror_path.symlink_to(rel_mirror_path)
            else:
                logging.warning(
                    "Script interpreter not found in AppDir: %s", interpreter_path
                )

    def _deploy_check_glibc_binary(self):
        """Deploys the glibc check binary"""

        glibc_check_binary_path = (
            self.context.binaries_resolver.resolve_check_glibc_binary(
                self.context.main_arch
            )
        )
        glibc_check_binary_target_path = self._module_dir / "check"

        # ensure the target directory exists
        glibc_check_binary_target_path.parent.mkdir(parents=True, exist_ok=True)

        # copy  check glibc binary
        shutil.copy(glibc_check_binary_path, glibc_check_binary_target_path)

        # make binary executable
        os.chmod(glibc_check_binary_target_path, 0o755)

    def _is_file_in_a_module(self, file: AppDirFileInfo):
        """Checks if a file belongs to a module"""

        path_str = file.path.__str__()
        return path_str.startswith(self.context.modules_dir.__str__())
