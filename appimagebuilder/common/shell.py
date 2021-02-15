import logging
import os
import shutil
import subprocess
import tempfile


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


def execute(script, env=None):
    if env is None:
        env = {}

    if not script:
        return

    if isinstance(script, list):
        script = "\n".join(script)

    run_env = os.environ.copy()
    for k, v in env.items():
        run_env[k] = v

    with tempfile.NamedTemporaryFile() as exported_env:
        run_env["BUILDER_ENV"] = exported_env.name

        _proc = subprocess.Popen(["bash", "-ve"], stdin=subprocess.PIPE, env=run_env)
        _proc.communicate(script.encode())

        if _proc.returncode != 0:
            raise RuntimeError("Script exited with code: %s" % _proc.returncode)

        exported_env.seek(0, 0)
        for line in exported_env.readlines():
            line = line.decode().strip()
            logging.info("Exporting env: %s" % line)
            key, val = line.split("=", 1)
            os.environ[key] = val
