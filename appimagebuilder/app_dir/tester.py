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

            self.client = docker.from_env()
            self.logger = logging.getLogger("TEST CASE '%s'" % self.name)

        def run(self):
            logging.info("")
            logging.info("Running test: %s" % self.name)
            logging.info("-----------------------------")

            volumes = self._get_container_volumes()
            environment = self.get_container_environment()

            container = self.client.containers.run(
                self.image,
                "/bin/sh",
                working_dir="/app",
                volumes=volumes,
                environment=environment,
                devices=["/dev/snd"],
                cap_add=["SYS_PTRACE"],
                tty=True,
                detach=True,
                auto_remove=True,
            )

            try:
                self.logger.info("before command")
                self._run_command(
                    "useradd -mu %s %s" % (os.getuid(), os.getenv("USER")), container
                )
                self._run_command(
                    "mkdir -p /home/%s/.config" % os.getenv("USER"),
                    container,
                    user=os.getenv("USER"),
                )

                self.logger.info("command")
                self._run_command(self.command, container, user=os.getenv("USER"))
            finally:
                container.kill()

        def _run_command(self, command, container, user="root"):
            print("$ %s" % command)
            exit_code, output = container.exec_run(command, user=user, tty=True)
            for line in output.decode("utf-8").splitlines():
                print(line)

            if exit_code != 0:
                print("$ %s FAILED, exit code: %s" % (command, exit_code))
                raise Tester.TestFailed()

        def _print_container_logs(self, ctr):
            logs = ctr.logs(stream=True)
            for line in logs:
                self.logger.info(line.decode("utf-8").strip())

        def _get_container_volumes(self):
            volumes = {self.app_dir: {"bind": "/app", "mode": "ro"}}

            if self.use_host_x:
                volumes["/tmp/.X11-unix"] = {"bind": "/tmp/.X11-unix", "mode": "rw"}

            dbus_session_address = os.getenv("DBUS_SESSION_BUS_ADDRESS")

            if dbus_session_address:
                regex = re.compile("unix:path=(?P<dbus_path>(\/\w+)+)")
                search_result = regex.search(dbus_session_address)
                if search_result:
                    volumes[search_result.group(1)] = {
                        "bind": search_result.group(1),
                        "mode": "rw",
                    }

            return volumes

        def get_container_environment(self):
            if self.use_host_x:
                self.env.append("DISPLAY=%s" % os.getenv("DISPLAY"))

            dbus_session_address = os.getenv("DBUS_SESSION_BUS_ADDRESS")
            if dbus_session_address:
                self.env.append("DBUS_SESSION_BUS_ADDRESS=%s" % dbus_session_address)

            self.env.append("UID=%s" % os.getuid())
            self.env.append("UNAME=%s" % os.getenv("USER"))
            self.env.append("XDG_DATA_DIRS=/usr/share:/usr/local/share")
            return self.env

    def __init__(self, recipe):
        self.recipe = recipe
        self.app_dir = os.path.abspath(recipe.get_item("AppDir/path"))

        self.tests = []
        self._load_config()

    def _load_config(self):
        tests_path = "AppDir/test"
        tests_conf = self.recipe.get_item(tests_path, [])
        for k, v in tests_conf.items():
            test_case = self._create_test_case(k, tests_path)
            self.tests.append(test_case)

    def _create_test_case(self, k, tests_path):
        test_case = Tester.TestCase(self.app_dir, k)
        test_case.image = self.recipe.get_item("%s/%s/image" % (tests_path, k))
        test_case.command = self.recipe.get_item(
            "%s/%s/command" % (tests_path, k), "./AppRun"
        )
        test_case.use_host_x = self.recipe.get_item(
            "%s/%s/use_host_x" % (tests_path, k), False
        )
        test_case.env = self.recipe.get_item("%s/%s/env" % (tests_path, k), [])
        if isinstance(test_case.env, dict):
            test_case.env = ["%s=%s" % (k, v) for k, v in test_case.env.items()]

        return test_case

    def run_tests(self):
        logging.info("============")
        logging.info("AppDir tests")
        logging.info("============")

        for test in self.tests:
            try:
                test.run()
            except Tester.TestFailed:
                raise
            except Exception as e:
                raise Tester.TestFailed("Execution failed. Error message: %s" % e)
