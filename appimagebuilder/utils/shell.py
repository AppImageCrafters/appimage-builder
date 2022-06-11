import logging
import shutil


class CommandNotFoundError(RuntimeError):
    pass


def require_executables(executables: [str]):
    """
    Iterates through all items in <executables> searching for their paths
    :return: map with the command name and its path
    """
    paths = {}
    for dep in executables:
        paths[dep] = require_executable(dep)
    return paths


def require_executable(tool):
    tool_path = shutil.which(tool)
    if not tool_path:
        raise CommandNotFoundError("Could not find '{exe}' on $PATH.".format(exe=tool))

    return tool_path


def assert_successful_result(proc):
    if proc.returncode:
        logging.error('"%s" execution failed' % proc.args)
        if proc.stderr:
            for line in proc.stderr.decode().splitlines():
                logging.error(line)

        raise RuntimeError(
            '"%s" execution failed with code %s' % (proc.args, proc.returncode)
        )
