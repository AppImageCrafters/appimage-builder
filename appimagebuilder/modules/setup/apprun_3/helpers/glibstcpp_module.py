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
import os
import shutil

from appimagebuilder.modules.setup import file_matching_patterns, apprun_utils
from appimagebuilder.modules.setup.apprun_3.apprun3_context import AppRun3Context
from appimagebuilder.modules.setup.apprun_3.helpers.base_helper import AppRun3Helper
from appimagebuilder.modules.setup.apprun_utils import replace_app_dir_in_path


class AppRun3GLibStdCppSetupHelper(AppRun3Helper):
    def __init__(self, context: AppRun3Context):
        super().__init__(context)

        self._module_dir = self.context.modules_dir / "glibstdcpp"
        self._glibstdcpp_module_files = []

    def run(self):
        self._glibstdcpp_module_files = self.context.app_dir.find(file_matching_patterns.glibstdcpp)

        if self._glibstdcpp_module_files:
            self._module_dir.mkdir(parents=True, exist_ok=True)

            self.context.app_dir.move_files(self._glibstdcpp_module_files, self._module_dir)
            self._deploy_check_glibstdcpp_binary()

            libstdcpp_version = self._extract_libstdcpp_version()
            library_paths = set([entry.path.parent for entry in self._glibstdcpp_module_files if entry.soname])

            self._generate_glibstdcpp_module_config(libstdcpp_version, library_paths)

    def _deploy_check_glibstdcpp_binary(self):
        glibstdcpp_check_binary_path = self.context.binaries_resolver.resolve_check_glibstdcpp_binary(
            self.context.main_arch)
        glibstdcpp_check_binary_target_path = self._module_dir / "check"

        # ensure the target directory exists
        glibstdcpp_check_binary_target_path.parent.mkdir(parents=True, exist_ok=True)

        # copy  check glibc binary
        shutil.copy(glibstdcpp_check_binary_path, glibstdcpp_check_binary_target_path)

        # make binary executable
        os.chmod(glibstdcpp_check_binary_target_path, 0o755)

    def _generate_glibstdcpp_module_config(self, libstdcpp_version, library_paths):
        library_paths = [replace_app_dir_in_path(self.context.app_dir.path, path) for path in library_paths]

        config = {
            "version": "1.0",
            "check": {
                "required_glibstdcpp": libstdcpp_version,
            },
            "module": {
                "library_paths": library_paths,
            },
        }

        # write the config file
        glibstdcpp_module_config_path = self._module_dir / "config"
        apprun_utils.write_config_file(config, glibstdcpp_module_config_path)

    def _extract_libstdcpp_version(self):
        version = None
        for entry in self._glibstdcpp_module_files:
            if entry.soname == 'libstdc++.so.6':
                # extract libstdc++ version from file name
                version = entry.path.name.split('.so.')[-1]
                break
        return version
