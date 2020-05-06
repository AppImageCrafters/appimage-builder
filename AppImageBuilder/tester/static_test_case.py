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
import re

import docker

from AppImageBuilder.tester.errors import TestFailed


class StaticTestCase:
    def __init__(self, docker_image, needed_libs):
        self.docker_image = docker_image
        self.needed_libs = needed_libs

        self.tests_utils_dir = None
        self.client = None
        self.logger = logging.getLogger("TEST CASE '%s'" % self.docker_image)

    def run(self):
        ctr = self._run_container()
        self._print_container_logs(ctr)
        result = ctr.wait()

        if result['StatusCode'] != 0:
            raise TestFailed(result['Error'])

    def _run_container(self):
        command = ['/utils/static_test.sh']
        command.extend(self.needed_libs)

        ctr = self.client.containers.run(self.docker_image, command, auto_remove=True, stdout=True, stderr=True,
                                         detach=True, volumes={self.tests_utils_dir: {'bind': '/utils', 'mode': 'ro'}})
        return ctr

    def _print_container_logs(self, ctr):
        logs = ctr.logs(stream=True)
        for line in logs:
            self.logger.info(line.decode('utf-8').strip())

    def setup(self):
        self.tests_utils_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), 'utils'))
        self.client = docker.from_env()
