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
import stat

import docker
import logging


class TestsTool:
    def __init__(self, app_dir, test_scenarios):
        self.app_dir = app_dir
        self.test_scenarios = test_scenarios
        self.client = docker.from_env()
        self.tests_dir_path = '/tmp/appimage-builder-tests-env'
        self.tests_wrapper_path = os.path.join(self.tests_dir_path, 'test_wrapper.sh')
        self.logger = logging.getLogger('test')

    def run_tests(self):
        logging.info("Running app tests")

        os.makedirs(self.tests_dir_path, exist_ok=True)
        self._write_host_x_share_wrapper()

        absolute_app_dir_path = os.path.abspath(self.app_dir.path)
        failed = []
        for k, v in self.test_scenarios.items():
            self.logger.info("Testing app on: %s" % k)
            test_logger = logging.getLogger('test:%s' % k)

            docker_image = v['image']
            command = v['command']
            try:
                volumes = {absolute_app_dir_path: {'bind': '/app', 'mode': 'ro'}}
                environment = []
                if 'env' in v:
                    environment = v['env']

                if 'use_host_x' in v and v['use_host_x']:
                    command = [self.tests_wrapper_path, command]
                    volumes['/tmp/.X11-unix'] = {'bind': '/tmp/.X11-unix', 'mode': 'rw'}
                    volumes[self.tests_dir_path] = {'bind': self.tests_dir_path, 'mode': 'rw'}
                    environment.append('DISPLAY=%s' % os.getenv('DISPLAY'))

                ctr = self.client.containers.run(docker_image, command, auto_remove=True, working_dir='/app',
                                                 volumes=volumes, stdout=True, stderr=True,
                                                 environment=environment, detach=True)

                logs = ctr.logs(stream=True)

                for line in logs:
                    test_logger.info(line.decode('utf-8').strip())

                result = ctr.wait()
                if result['StatusCode'] != 0:
                    test_logger.warning("Execution failed. Error message: %s" % result['Error'])
                    failed.append(k)

            except Exception as err:
                test_logger.warning("Execution failed. Error message: %s" % err)
                failed.append(k)

        self.logger.info("Tests results:")
        for k, v in self.test_scenarios.items():
            result = "failed" if k in failed else "passed"
            self.logger.info(" - %s : %s" % (k, result))

    def _write_host_x_share_wrapper(self):
        with open(self.tests_wrapper_path, 'w') as f:
            f.write('\n'.join([
                '#!/bin/bash',
                'set -e',
                'useradd test',
                'su test -c "$@"',
            ]))

        os.chmod(self.tests_wrapper_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH)
