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

from appimagebuilder.modules.analisys.inspector import Inspector
from appimagebuilder.modules.test.errors import TestFailed


class DependenciesTest:
    def __init__(self, appdir, docker_image):
        self.appdir = appdir
        self.docker_image = docker_image
        self.logger = logging.getLogger("Dependencies test on '%s'" % self.docker_image)

        self.tests_utils_dir = os.path.realpath(
            os.path.join(os.path.dirname(__file__), "utils")
        )
        self.client = docker.from_env()

    def run(self):
        self.logger.info("Looking for missing dependencies")
        need_libs = self._list_needed_libs()
        container_libs = self._list_container_libs()

        missing_libs = [lib for lib in need_libs if lib not in container_libs]
        for lib in missing_libs:
            self.logger.error("Missing library '%s'" % lib)

        if missing_libs:
            raise TestFailed("Some libraries cannot be located in the docker image.")
        else:
            self.logger.info("Success, all dependencies were found!")

    def _list_needed_libs(self):
        inspector = Inspector(self.appdir)
        return inspector.get_bundle_needed_libs()

    def _list_container_libs(self):
        output = self.client.containers.run(
            self.docker_image,
            "/sbin/ldconfig -p",
            tty=True,
            auto_remove=True,
        )

        results = re.findall(".*\s=>\s/.*/(.*)", output.decode("utf-8"))
        container_libs = set([result.strip() for result in results])

        return container_libs
