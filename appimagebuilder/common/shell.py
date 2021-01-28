import os
import pty
import shutil


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
            raise RuntimeError("Could not find '{exe}' on $PATH.".format(exe=dep))
    return paths


def assert_successful_result(proc):
    if proc.returncode:
        raise RuntimeError(
            '"%s" execution failed with code %s' % (proc.args, proc.returncode)
        )


def execute(script):
    if not script:
        return

    if isinstance(script, str):
        script = script.splitlines()

    # log each command before running it
    script = [
        "echo %s$ %s && %s" % (os.path.abspath(os.curdir), item, item)
        for item in script
    ]
    script = " && ".join(script)

    shell = os.environ.get("SHELL", "sh")
    ret = pty.spawn([shell, "-c", script])
    if ret != 0:
        raise RuntimeError("Script exited with code %s", ret)
