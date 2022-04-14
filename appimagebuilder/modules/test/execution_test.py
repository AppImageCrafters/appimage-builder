#   Copyright  2020 Alexis Lopez Zubieta
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#   sell copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.

import logging
import os
import re
from pathlib import Path

import docker

from appimagebuilder.modules.test.errors import TestFailed


class ExecutionTest:
    def __init__(self, appdir: Path, name, image, command, env: [str] = None):
        if env is None:
            env = []

        self.appdir = appdir
        self.name = name
        self.image = image
        self.command = command
        self.env = env

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
                "useradd -mu %s %s" % (os.getuid(), os.getenv("USER")),
                container,
                accepted_exit_codes=[0, 9],
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

    def _run_command(self, command, container, user="root", accepted_exit_codes=None):
        if accepted_exit_codes is None:
            accepted_exit_codes = [0]

        print("$ %s" % command)
        exit_code, output = container.exec_run(command, user=user, tty=True)
        print(output.decode())

        if exit_code not in accepted_exit_codes:
            print("$ %s FAILED, exit code: %s" % (command, exit_code))
            raise TestFailed()

    def _print_container_logs(self, ctr):
        logs = ctr.logs(stream=True)
        for line in logs:
            self.logger.info(line.decode("utf-8").strip())

    def _get_container_volumes(self):
        volumes = {
            self.appdir: {"bind": "/app", "mode": "ro"},
            "/tmp/.X11-unix": {"bind": "/tmp/.X11-unix", "mode": "rw"}
        }

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
        self.env.append("DISPLAY=%s" % os.getenv("DISPLAY"))

        dbus_session_address = os.getenv("DBUS_SESSION_BUS_ADDRESS")
        if dbus_session_address:
            self.env.append("DBUS_SESSION_BUS_ADDRESS=%s" % dbus_session_address)

        self.env.append("UID=%s" % os.getuid())
        self.env.append("UNAME=%s" % os.getenv("USER"))
        self.env.append("XDG_DATA_DIRS=/usr/share:/usr/local/share")
        return self.env
