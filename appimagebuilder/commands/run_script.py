#  Copyright  2021 Alexis Lopez Zubieta
#
#  Permission is hereby granted, free of charge, to any person obtaining a
#  copy of this software and associated documentation files (the "Software"),
#  to deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
import logging
import os
import subprocess
import tempfile

from appimagebuilder.commands.command import Command
from appimagebuilder.context import Context
from appimagebuilder.recipe.roamer import Roamer


class RunScriptCommand(Command):
    """
    Execute a given set of instructions on bash using appdir as workdir and the given env
    variables
    """

    def __init__(
        self, context: Context, script: Roamer, description: str = "script", env=None
    ):
        super().__init__(context, description)

        self.script = script

        if not env:
            env = {}
        self.env = env

    def id(self):
        return "shell"

    def __call__(self, *args, **kwargs):
        # resolve value
        self.script = self.script()

        if not self.script:
            return

        if isinstance(self.script, list):
            self.script = "\n".join(self.script)

        run_env = os.environ.copy()
        for k, v in self.env.items():
            run_env[k] = v

        with tempfile.NamedTemporaryFile() as exported_env:
            run_env["BUILDER_ENV"] = exported_env.name
            run_env["RECIPE"] = str(self.context.recipe_path.absolute())
            run_env["BUILD_DIR"] = str(self.context.build_dir.absolute())
            run_env["SOURCE_DIR"] = str(self.context.recipe_path.parent.absolute())
            run_env["TARGET_APPDIR"] = str(self.context.app_dir.absolute())

            _proc = subprocess.Popen(
                ["bash", "-ve"], stdin=subprocess.PIPE, env=run_env
            )
            _proc.communicate(self.script.encode())

            if _proc.returncode != 0:
                raise RuntimeError("Script exited with code: %s" % _proc.returncode)

            self._load_exported_env(exported_env)

    @staticmethod
    def _load_exported_env(exported_env):
        exported_env.seek(0, 0)
        for line in exported_env.readlines():
            line = line.decode().strip()
            logging.info("Exporting env: %s" % line)
            key, val = line.split("=", 1)
            os.environ[key] = val
