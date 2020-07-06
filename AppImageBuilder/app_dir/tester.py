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
import stat
import tempfile

import docker


class Tester:
    class TestFailed(RuntimeError):
        pass

    class TestCase:
        def __init__(self, app_dir, name):
            self.app_dir = app_dir
            self.name = name
            self.image = None
            self.command = None
            self.use_host_x = False
            self.env = []

            self.temp_dir = None
            self.tests_wrapper_path = None
            self.client = None
            self.logger = logging.getLogger("TEST CASE '%s'" % self.name)

        def run(self):
            logging.info("")
            logging.info("Running test: %s" % self.name)
            logging.info("-----------------------------")

            self.logger.info("Executing: %s" % self.command)
            ctr = self._run_container()
            self._print_container_logs(ctr)
            result = ctr.wait()

            if result['StatusCode'] != 0:
                raise Tester.TestFailed(result['Error'])

        def _run_container(self):
            volumes = self._get_container_volumes()
            command = self._get_container_command()
            environment = self.get_container_environment()

            ctr = self.client.containers.run(self.image, command, auto_remove=True, working_dir='/app',
                                             volumes=volumes, stdout=True, stderr=True, cap_add=['SYS_PTRACE'],
                                             environment=environment, detach=True, devices=['/dev/snd'])
            return ctr

        def _print_container_logs(self, ctr):
            logs = ctr.logs(stream=True)
            for line in logs:
                self.logger.info(line.decode('utf-8').strip())

        def _get_container_volumes(self):
            volumes = {self.app_dir: {'bind': '/app', 'mode': 'ro'}}

            if self.use_host_x:
                volumes['/tmp/.X11-unix'] = {'bind': '/tmp/.X11-unix', 'mode': 'rw'}
                volumes[self.temp_dir.name] = {'bind': self.temp_dir.name, 'mode': 'rw'}

            dbus_session_address = os.getenv('DBUS_SESSION_BUS_ADDRESS')

            if dbus_session_address:
                regex = re.compile('unix:path=(?P<dbus_path>(\/\w+)+)')
                search_result = regex.search(dbus_session_address)
                if search_result:
                    volumes[search_result.group(1)] = {'bind': search_result.group(1), 'mode': 'rw'}

            return volumes

        def setup(self):
            self.temp_dir = tempfile.TemporaryDirectory()
            self.tests_wrapper_path = os.path.join(self.temp_dir.name, 'test_wrapper.sh')
            self.client = docker.from_env()
            if self.use_host_x:
                self._write_host_x_share_wrapper()

        def teardown(self):
            self.temp_dir.cleanup()

        def _write_host_x_share_wrapper(self):
            with open(self.tests_wrapper_path, 'w') as f:
                f.write('\n'.join([
                    '#!/bin/sh',
                    'set -e',
                    'useradd -mu $UID $UNAME',
                    'export HOME=/home/$UNAME'
                    'export XDG_DATA_DIRS=/usr/share',
                    'su $UNAME -c "$@"',
                ]))

            os.chmod(self.tests_wrapper_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH)

        def _get_container_command(self):
            if self.use_host_x:
                return [self.tests_wrapper_path, self.command]
            else:
                return self.command

        def get_container_environment(self):
            if self.use_host_x:
                self.env.append('DISPLAY=%s' % os.getenv('DISPLAY'))

            dbus_session_address = os.getenv('DBUS_SESSION_BUS_ADDRESS')
            if dbus_session_address:
                self.env.append('DBUS_SESSION_BUS_ADDRESS=%s' % dbus_session_address)

            self.env.append('UID=%s' % os.getuid())
            self.env.append('UNAME=%s' % os.getenv("USER"))
            return self.env

    def __init__(self, recipe):
        self.recipe = recipe
        self.app_dir = os.path.abspath(recipe.get_item('AppDir/path'))

        self.tests = []
        self._load_config()

    def _load_config(self):
        tests_path = 'AppDir/test'
        tests_conf = self.recipe.get_item(tests_path, [])
        for k, v in tests_conf.items():
            test_case = self._create_test_case(k, tests_path)
            self.tests.append(test_case)

    def _create_test_case(self, k, tests_path):
        test_case = Tester.TestCase(self.app_dir, k)
        test_case.image = self.recipe.get_item('%s/%s/image' % (tests_path, k))
        test_case.command = self.recipe.get_item('%s/%s/command' % (tests_path, k), './AppRun')
        test_case.use_host_x = self.recipe.get_item('%s/%s/use_host_x' % (tests_path, k), False)
        test_case.env = self.recipe.get_item('%s/%s/env' % (tests_path, k), [])
        if isinstance(test_case.env, dict):
            test_case.env = ["%s=%s" % (k, v) for k, v in test_case.env.items()]

        return test_case

    def run_tests(self):
        logging.info("============")
        logging.info("AppDir tests")
        logging.info("============")

        for test in self.tests:
            try:
                test.setup()
                test.run()
            except Tester.TestFailed:
                raise
            except Exception as e:
                raise Tester.TestFailed("Execution failed. Error message: %s" % e)
            finally:
                test.teardown()
