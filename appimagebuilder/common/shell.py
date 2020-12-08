import os
import shlex
import shutil
import subprocess
import sys
import logging


class ShellCommandError(RuntimeError):
    pass


def resolve_commands_paths(commands: [str]):
    """
    Iterates through all items in <commands> searching for their paths
    :return: map with the command name and its path
    """
    paths = {}
    for dep in commands:
        paths[dep] = shutil.which(dep)
        if paths[dep] is None:
            # shutil.which returns None if the executable
            # was not found on PATH
            raise ShellCommandError("Could not find '{exe}' on $PATH.".format(exe=dep))
    return paths


def run_command(
    command,
    stdout=sys.stdout,
    assert_success=True,
    wait_for_completion=True,
    wait_for_completion_timeout=None,
    env=None,
    **kwargs
):
    """
    Runs a command as a subprocess
    :param command: command to execute, does not need to be formatted
    :param stdout: where to pipe the standard output
    :param assert_success: should we check if the process succeeded?
    :param wait_for_completion: should we wait for completion?
    :param wait_for_completion_timeout: if yes, how much?
    :param kwargs: additional params which should be passed to format
    :param env: environment to be used while running the command
    :return:
    """
    command = command.format(**kwargs)
    # log it
    logging.debug(command)

    if not env:
        env = os.environ

    # need to split the command into args
    proc = subprocess.Popen(
        shlex.split(command), stdout=stdout, stdin=sys.stdin, stderr=sys.stderr, env=env
    )

    if wait_for_completion:
        proc.wait(wait_for_completion_timeout)

    if assert_success:
        assert_command_successful_output(proc)

    # return the process instance for future use
    # if necessary
    return proc


def assert_command_successful_output(proc):
    if proc.returncode:
        raise ShellCommandError(
            '"%s" execution failed with code %s' % (proc.args, proc.returncode)
        )
