import shutil
import subprocess


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

    if isinstance(script, list):
        script = "\n".join(script)

    _proc = subprocess.Popen(["bash", "-ve"], stdin=subprocess.PIPE)
    _proc.communicate(script.encode())

    if _proc.returncode != 0:
        raise RuntimeError("Script exited with code: %s" % _proc.returncode)
