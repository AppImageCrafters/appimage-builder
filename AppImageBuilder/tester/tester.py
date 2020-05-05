#  Copyright  2020 Alexis Lopez Zubieta
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

from AppImageBuilder.common.appimage_mount import appimage_umount, appimage_mount
from AppImageBuilder.tester.test_case import DockerTestCase, TestFailed


class Tester:

    def __init__(self, target):
        self.target = target
        if os.path.isfile(self.target):
            self.app_dir, self.appimage_process = appimage_mount(target)
        else:
            self.app_dir = os.path.abspath(target)
            self.appimage_process = None

    def __del__(self):
        if self.appimage_process:
            appimage_umount(self.appimage_process)

    def _create_test_case(self, docker_image, command='./AppRun', use_host_x=True, env=None):
        if env is None:
            env = []

        test_case = DockerTestCase(self.app_dir, docker_image)
        test_case.image = docker_image
        test_case.command = command
        test_case.use_host_x = use_host_x
        test_case.env = env
        return test_case

    def run_test(self, docker_image):
        test_case = self._create_test_case(docker_image)
        try:
            test_case.setup()
            test_case.run()
        except TestFailed:
            raise
        except Exception as e:
            raise TestFailed("Execution failed. Error message: %s" % e)
