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
import logging
import os

from AppImageBuilder.common.appimage_mount import appimage_umount, appimage_mount
from AppImageBuilder.inspector.inspector import Inspector
from AppImageBuilder.tester.static_test_case import StaticTestCase
from AppImageBuilder.tester.test_case import TestCase, TestFailed


class Tester:

    def __init__(self, target):
        self.target = target
        self.needed_libs = None

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

        test_case = TestCase(self.app_dir, docker_image)
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

    def run_static_test(self, docker_image):
        if not self.needed_libs:
            logging.info("Building bundle dependencies list")
            inspector = Inspector(self.app_dir)
            self.needed_libs = inspector.get_bundle_needed_libs()

        test_case = StaticTestCase(docker_image, self.needed_libs)
        try:
            test_case.setup()
            test_case.run()
        except TestFailed:
            raise
        except Exception as e:
            raise TestFailed("Execution failed. Error message: %s" % e)
