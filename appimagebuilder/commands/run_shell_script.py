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


class RunShellScriptCommand(Command):
    """
    Execute a given set of instructions on bash using appdir as workdir and the given env
    variables
    """

    def __init__(self, context: Context, description, instructions: Roamer, env=None):
        super().__init__(context, description)

        self.instructions = instructions

        if not env:
            env = {}
        self.env = env

    def id(self):
        return "shell"

    def __call__(self, *args, **kwargs):
        # resolve value
        self.instructions = self.instructions()

        if not self.instructions:
            return

        if isinstance(self.instructions, list):
            self.instructions = "\n".join(self.instructions)

        run_env = os.environ.copy()
        for k, v in self.env.items():
            run_env[k] = v

        with tempfile.NamedTemporaryFile() as exported_env:
            run_env["BUILDER_ENV"] = exported_env.name
            run_env["APPDIR"] = str(self.context.app_dir)

            _proc = subprocess.Popen(
                ["bash", "-ve"], stdin=subprocess.PIPE, env=run_env
            )
            _proc.communicate(self.instructions.encode())

            if _proc.returncode != 0:
                raise RuntimeError("Script exited with code: %s" % _proc.returncode)

            self._load_exported_env(exported_env)

    def _load_exported_env(self, exported_env):
        exported_env.seek(0, 0)
        for line in exported_env.readlines():
            line = line.decode().strip()
            logging.info("Exporting env: %s" % line)
            key, val = line.split("=", 1)
            os.environ[key] = val
