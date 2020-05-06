import logging
import os
import re

import docker


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

        self.tests_utils_dir = None
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
            raise TestFailed(result['Error'])

    def _run_container(self):
        volumes = self._get_container_volumes()
        command = self._get_container_command()
        environment = self.get_container_environment()

        ctr = self.client.containers.run(self.image, command, auto_remove=True, working_dir='/app',
                                         volumes=volumes, stdout=True, stderr=True, cap_add=['SYS_PTRACE', 'SYS_ADMIN'],
                                         environment=environment, detach=True, devices=['/dev/snd', '/dev/fuse'])
        return ctr

    def _print_container_logs(self, ctr):
        logs = ctr.logs(stream=True)
        for line in logs:
            self.logger.info(line.decode('utf-8').strip())

    def _get_container_volumes(self):
        volumes = {self.app_dir: {'bind': '/app', 'mode': 'ro'}}

        if self.use_host_x:
            volumes['/tmp/.X11-unix'] = {'bind': '/tmp/.X11-unix', 'mode': 'rw'}
            volumes[self.tests_utils_dir] = {'bind': '/utils'}

        dbus_session_address = os.getenv('DBUS_SESSION_BUS_ADDRESS')

        if dbus_session_address:
            regex = re.compile('unix:path=(?P<dbus_path>(\/\w+)+)')
            search_result = regex.search(dbus_session_address)
            if search_result:
                volumes[search_result.group(1)] = {'bind': search_result.group(1), 'mode': 'rw'}

        return volumes

    def setup(self):
        self.tests_utils_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), 'utils'))
        self.client = docker.from_env()

    def _get_container_command(self):
        if self.use_host_x:
            return ['/utils/entry_point.sh', self.command]
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
