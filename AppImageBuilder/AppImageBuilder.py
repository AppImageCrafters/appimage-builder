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
import platform

from AppImageBuilder import AppDir2
from AppImageBuilder.AppRun import AppRun
from AppImageBuilder.tools.TestsTool import TestsTool
from AppImageBuilder.tools.AppImageTool import AppImageTool
from AppImageBuilder.tools.ShellTool import ShellTool


class AppImageBuilder:
    app_dir = None
    app_config = {}
    app_dir_config = {}

    script = []
    drivers = None
    logger = None

    def __init__(self):
        self.logger = logging.getLogger('builder')

    def _load_app_dir(self):
        absolute_app_dir_path = os.path.abspath(self.app_dir_config['path'])

        self.app_dir = AppDir2(absolute_app_dir_path)

    def run_script(self):
        if self.script:
            self.logger.info("Running script")
            shell = ShellTool()
            shell.execute(self.script)

            self.logger.info("Script completed")
        else:
            self.logger.info("No 'script' entry in the recipe.")

    def build_app_dir(self):
        if not self.app_dir:
            self._load_app_dir()

        self._bundle_dependencies()
        self.configure_app_dir()
        self.logger.info("AppDir build completed")

    def _bundle_dependencies(self):
        self.logger.info("Bundling dependencies into the AppDir: %s" % self.app_dir.path)
        lockup_queue = {}
        self._queue_dependencies(lockup_queue, self._load_base_dependencies())

        while lockup_queue:
            path, dependency = lockup_queue.popitem()

            self.logger.info("Inspecting: %s" % path)
            new_dependencies = self._lockup_new_dependencies(dependency)
            self._queue_dependencies(lockup_queue, new_dependencies)

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

    def configure_app_dir(self):
        exec = self.app_dir_config['exec']
        exec_args = self.app_dir_config['exec_args'] if 'exec_args' in self.app_dir_config else None

        self.logger.info("Configuring AppDir")
        self.app_dir.app_run = AppRun(exec, exec_args)

        for driver in self.drivers.values():
            driver.configure(self.app_dir)

        app_run_path = os.path.join(self.app_dir.path, "AppRun")
        self.app_dir.app_run.save(app_run_path)

    def test_app_dir(self):
        if not self.app_dir:
            self._load_app_dir()

        if 'test' in self.app_dir_config:
            tests_tool = TestsTool(self.app_dir, self.app_dir_config['test'])
            tests_tool.run_tests()

    def build_appimage(self):
        if not self.app_dir:
            self._load_app_dir()

        self.logger.info("Build AppImage")
        appimage_tool = AppImageTool()

        info_driver = self.drivers['info']
        app_name = info_driver.config['name'].replace(' ', '_')
        app_version = info_driver.config['version']
        output_file = os.path.join(os.getcwd(), "%s-%s-%s.AppImage" % (app_name, app_version, platform.machine()))

        appimage_tool.bundle(self.app_dir.path, output_file)

    def _queue_dependencies(self, lockup_queue, dependencies):
        for dependency in dependencies:
            if dependency.source not in lockup_queue:
                lockup_queue[dependency.source] = dependency
