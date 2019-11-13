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
from AppImageCraft import drivers


class AppDir2:
    path = None
    lockup_queue = None
    drivers = []

    def __init__(self, path):
        assert os.path.exists(path)
        assert os.path.isdir(path)

        self.path = path
        self.drivers.append(drivers.Linker())
        self.drivers.append(drivers.Dpkg())

        self.lockup_queue = self.list_app_dir_files()

    def list_app_dir_files(self):
        file_list = list()

        for root, dirs, files in os.walk(self.path):
            for filename in files:
                file_list.append(os.path.join(root, filename))

        return file_list

    def bundle_dependencies(self):
        while self.lockup_queue:
            file = self.lockup_queue.pop()

            dependencies = self._lockup_file_dependencies(file)
            dependencies = self._filter_bundled_dependencies(dependencies)

            self._deploy_dependencies(dependencies)
            self._queue_for_lockup(dependencies)

    def _lockup_file_dependencies(self, file):
        dependencies = []
        for driver in self.drivers:
            driver_dependencies = driver.lockup_dependencies(file)
            if driver_dependencies:
                for dependency in driver_dependencies:
                    dependencies.append(dependency)

        return dependencies

    def _filter_bundled_dependencies(self, dependency_list):
        filtered_dependency_list = []
        for dependency in dependency_list:
            if not self._bundled(dependency.source):
                filtered_dependency_list.append(dependency)

        return filtered_dependency_list

    def _deploy_dependencies(self, dependency_list):
        for dependency in dependency_list:
            dependency.deploy(self)

    def _queue_for_lockup(self, dependencies):
        for dependency in dependencies:
            self.lockup_queue.append(dependency.source)

    def write_app_run(self, app_run_path):
        pass

    def write_app_dir_info(self):
        pass

    def _bundled(self, source):
        return os.path.exists(self.path + source)
