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
from AppImageCraft import AppDir2
from AppImageCraft import drivers
from AppImageCraft.AppRun import AppRun


class AppImageBuilder:
    app_dir = None
    app_config = {}
    app_dir_config = {}

    drivers = None

    def _load_app_dir(self):
        absolute_app_dir_path = os.path.abspath(self.app_dir_config['path'])

        self.app_dir = AppDir2(absolute_app_dir_path)

    def build(self):
        self._load_app_dir()
        self.bundle_dependencies()
        self.write_app_run(self.app_config['exec'])

    def bundle_dependencies(self):
        dependencies = self._load_base_dependencies()
        while dependencies:
            dependency = dependencies.pop()

            new_dependencies = self._lockup_new_dependencies(dependency)
            dependencies.extend(new_dependencies)

            if not self.app_dir.bundled(dependency.source):
                dependency.deploy(self.app_dir)

    def _lockup_new_dependencies(self, dependency):
        new_dependencies = self._lockup_file_dependencies(dependency.source)
        new_dependencies = [new_dependency for new_dependency in new_dependencies if
                            not self.app_dir.bundled(new_dependency.source)]

        return new_dependencies

    def _load_base_dependencies(self):
        dependencies = []
        for id, driver in self.drivers.items():
            base_dependencies = driver.list_base_dependencies(self.app_dir)
            if base_dependencies:
                dependencies.extend(base_dependencies)

        return dependencies

    def _lockup_file_dependencies(self, file):
        dependencies = []
        for driver in self.drivers.values():
            driver_dependencies = driver.lockup_file_dependencies(file, self.app_dir)
            if driver_dependencies:
                for dependency in driver_dependencies:
                    dependencies.append(dependency)

        return dependencies

    def write_app_run(self, exec):
        app_run = AppRun(exec)
        app_run_path = os.path.join(self.app_dir.path, "AppRun")

        for driver in self.drivers.values():
            driver.configure_app_run(app_run, self.app_dir)

        app_run.save(app_run_path)
