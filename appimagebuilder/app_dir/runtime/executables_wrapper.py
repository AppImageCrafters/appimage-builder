import os
import shutil
import stat
from pathlib import Path


class ExecutablesWrapper:
    def __init__(self, apprun_path):
        self.apprun_path = Path(apprun_path)

    def wrap(self, path: str, args: [str], env: dict):
        path = Path(path)
        if self.is_wrapped(path):
            return

        wrapped_name = str(path) + ".orig"
        path.rename(wrapped_name)

        env_path = str(path) + ".env"
        self.write_env(env_path, env)
        shutil.copyfile(self.apprun_path, path, follow_symlinks=True)
        os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def is_wrapped(self, path):
        return path.name.endswith(".orig")

    def write_env(self, env_path, env):
        with open(env_path, "w") as f:
            f.write(str(env))
