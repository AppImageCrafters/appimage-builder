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
import docker
import logging


class TestsTool:
    def __init__(self, app_dir, test_scenarios):
        self.app_dir = app_dir
        self.test_scenarios = test_scenarios
        self.client = docker.from_env()

    def run_tests(self):
        logging.info("Running app tests")
        absolute_app_dir_path = os.path.abspath(self.app_dir.path)
        failed = []
        for k, v in self.test_scenarios.items():
            logging.info("Testing app on: %s" % k)
            docker_image = v['image']
            command = v['command']
            try:
                output = self.client.containers.run(docker_image, command, auto_remove=True, working_dir='/app',
                                                    volumes={absolute_app_dir_path: {'bind': '/app', 'mode': 'ro'}},
                                                    stdout=True)
                logging.debug(output.decode('utf-8'))
            except Exception as err:
                logging.warning("Execution failed: %s" % err)
                failed.append(k)

        logging.info("Tests results:")
        for k, v in self.test_scenarios.items():
            result = "failed" if k in failed else "passed"
            logging.info(" - %s : %s" % (k, result))
