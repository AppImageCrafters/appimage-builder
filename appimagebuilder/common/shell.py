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


def assert_successful_result(proc):
    if proc.returncode:
        raise ShellCommandError(
            '"%s" execution failed with code %s' % (proc.args, proc.returncode)
        )
