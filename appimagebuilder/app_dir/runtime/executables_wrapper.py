import os
import shutil
import stat
from pathlib import Path

from appimagebuilder.app_dir.runtime.executables import Executable


class ExecutablesWrapper:
    def __init__(self, apprun_path: str, appdir_path: str, env: dict):
        self.apprun_path = Path(apprun_path)
        self.appdir_path = Path(appdir_path)
        self.env = env if env else {}

    def wrap(self, executable: Executable, user_env: dict):
        if self.is_wrapped(executable.path):
            return

        wrapped_path = str(executable.path) + ".orig"
        os.rename(executable.path, wrapped_path)

        self._deploy_env(executable, wrapped_path, user_env)
        self._deploy_apprun(executable.path)

    def _deploy_apprun(self, target_path):
        shutil.copyfile(self.apprun_path, target_path, follow_symlinks=True)
        os.chmod(
            target_path,
            stat.S_IRUSR
            | stat.S_IRGRP
            | stat.S_IROTH
            | stat.S_IXUSR
            | stat.S_IXGRP
            | stat.S_IXOTH,
        )

    def is_wrapped(self, path):
        return path.name.endswith(".orig")

    @staticmethod
    def _serialize_dict_to_dot_env(env: dict):
        lines = []
        for k, v in env.items():
            if isinstance(v, str):
                lines.append("%s=%s\n" % (k, v))

            if isinstance(v, list):
                if k == "EXEC_ARGS":
                    lines.append("%s=%s\n" % (k, " ".join(v)))
                else:
                    lines.append("%s=%s\n" % (k, ":".join(v)))

            if isinstance(v, dict):
                entries = ["%s:%s;" % (k, v) for (k, v) in v.items()]
                lines.append("%s=%s\n" % (k, "".join(entries)))

        return "".join(lines)

    def _deploy_env(self, executable, wrapped_path, user_env):
        apprun_env = self._generate_executable_env(executable, wrapped_path, user_env)
        env_path = str(executable.path) + ".env"
        with open(env_path, "w") as f:
            f.write(self._serialize_dict_to_dot_env(apprun_env))

    def _generate_executable_env(self, executable, wrapped_path, user_env):
        executable_dir = os.path.dirname(executable.path)
        apprun_env = {
            "APPDIR": "$ORIGIN/" + os.path.relpath(self.appdir_path, executable_dir),
            "EXEC": "$APPDIR/" + os.path.relpath(wrapped_path, self.appdir_path),
            "EXEC_ARGS": executable.args,
        }

        # set defaults
        for k, v in self.env.items():
            apprun_env[k] = v

        # override defaults with the user_env
        for k, v in user_env.items():
            apprun_env[k] = v

        return apprun_env
