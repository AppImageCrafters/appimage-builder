#  Copyright  2019 Alexis Lopez Zubieta
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
import logging
from AppImageCraft.LinkerTool import LinkerTool
from AppImageCraft.PkgTool import PkgTool


class AppDirIsolator:
    app_dir_path = None
    deploy_map = None
    libs_map = None

    def __init__(self, dir):
        self.pkg_tool = PkgTool()
        self.logger = logging.getLogger("AppDirIsolator")

        self.app_dir_path = dir
        self.deploy_map = {}
        self.libs_map = {}
        self.linker = None

    def isolate(self):
        self.deploy_linker()

        pending_files = self.list_files_with_external_dependencies()

        while pending_files:
            for file in pending_files:
                self.deploy_file_dependencies(file)

            pending_files = self.list_files_with_external_dependencies()

    def deploy_file_dependencies(self, file):
        dependencies_map = self.linker.list_link_dependencies(file)
        self.logger.info("Deploying external dependencies of %s" % file)

        for dependency_file_path in dependencies_map.values():
            if dependency_file_path:
                target_file_path = self.app_dir_path + dependency_file_path
                if os.path.exists(target_file_path):
                    self.logger.info("%s is already deployed, skipping" % dependency_file_path)
                    continue
                if dependency_file_path.startswith(self.app_dir_path):
                    self.logger.info("%s is an inner dependency, skipping" % dependency_file_path)
                    continue

                self.deploy_package_of(dependency_file_path)
        print(dependencies_map)
        self.libs_map = {**self.libs_map, **dependencies_map}

    def list_files_with_external_dependencies(self):
        file_list = set()
        library_dirs = self.generate_inner_link_paths()
        linkable_files = self.linker.list_linkable_files(self.app_dir_path)

        for file in linkable_files:
            dependencies_map = self.linker.list_link_dependencies(file, True, library_dirs)
            for dependency_file_path in dependencies_map.values():
                if dependency_file_path \
                        and not dependency_file_path.startswith(self.app_dir_path) \
                        and not os.path.exists(self.app_dir_path + dependency_file_path):
                    file_list.add(file)

        return list(file_list)

    def deploy_package_of(self, file):
        packages = self.pkg_tool.find_owner_packages(file)
        deployed_files = self.pkg_tool.deploy_pkgs(packages, self.app_dir_path)

        for path,pkg in deployed_files.items():
            self.deploy_map[path] = pkg

    def deployed(self, file):
        return file.startswith(self.app_dir_path) or os.path.exists(self.app_dir_path + file)

    def list_missing_dependencies(self, file):
        pass

    def generate_inner_link_paths(self):
        elf_files = self.linker.list_libraries_files(self.app_dir_path)

        ld_paths = set()
        for file in elf_files:
            ld_paths.add(os.path.dirname(file))

        return list(ld_paths)

    def deploy_linker(self):
        if not self.linker or not self.linker.binary_path.startswith(self.app_dir_path):
            system_linker_path = LinkerTool.find_binary_path("/")
            self.deploy_package_of(system_linker_path)

            linker_path = LinkerTool.find_binary_path(self.app_dir_path)
            assert linker_path.startswith(self.app_dir_path)

            self.linker = LinkerTool(linker_path)

        self.logger.info("Using linker at: %s" % self.linker.binary_path)
