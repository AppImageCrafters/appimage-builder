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
import logging
import os
import platform
import stat
from urllib import request

from AppImageBuilder import AppDir2
from AppImageBuilder.AppRun import AppRun
from AppImageBuilder.tools import MkSquashFs
from AppImageBuilder.tools.ShellTool import ShellTool
from AppImageBuilder.tools.TestsTool import TestsTool


class AppImageBuilder:
    app_dir = None
    app_config = {}
    app_dir_config = {}
    appimage_config = {}

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

        supported_architectures = ["i686", "aarch64", "armhf", "x86_64"]
        target_arch = self.appimage_config['arch']
        if target_arch not in supported_architectures:
            self.logger.error("There is not a prebuild runtime for the %s architecture."
                              " You will have to build the AppImage runtime manually." % target_arch)

        runtime_url_template = "https://github.com/AppImage/AppImageKit/releases/download/continuous/runtime-%s"
        runtime_url = runtime_url_template % target_arch
        runtime_path = "AppRun-%s" % target_arch

        if not os.path.exists(runtime_path):
            self.logger.info("Downloading runtime: %s" % runtime_url_template % runtime_url)
            request.urlretrieve(runtime_url, runtime_path)

        mk_squash_fs_tool = MkSquashFs()
        squashfs_path = "AppDir.squashfs"
        self.logger.info("Compressing AppDir to: %s" % squashfs_path)
        mk_squash_fs_tool.make_squash_file_system(self.app_dir.path, squashfs_path)

        if 'name' in self.appimage_config:
            output_path = self.appimage_config['name']
        else:
            info_driver = self.drivers['info']
            app_name = info_driver.config['name'].replace(' ', '_')
            app_version = info_driver.config['version']
            output_path = os.path.join(os.getcwd(), "%s-%s-%s.AppImage" % (app_name, app_version, target_arch))

        with open(output_path, "wb") as appimage_file:
            with open(runtime_path, "rb") as runtime_file:
                buffer = runtime_file.read(1024)
                while buffer:
                    appimage_file.write(buffer)
                    buffer = runtime_file.read(1024)

            with open(squashfs_path, "rb") as squashfs_file:
                buffer = squashfs_file.read(1024)
                while buffer:
                    appimage_file.write(buffer)
                    buffer = squashfs_file.read(1024)

        os.chmod(output_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IWGRP | stat.S_IXOTH | stat.S_IWOTH)
        os.remove(squashfs_path)

    def _queue_dependencies(self, lockup_queue, dependencies):
        for dependency in dependencies:
            if dependency.source not in lockup_queue:
                lockup_queue[dependency.source] = dependency
