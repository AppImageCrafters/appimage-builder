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
from appimagebuilder.main.commands.create_appdir_command import CreateAppDirCommand
from appimagebuilder.main.commands.create_appimage_command import CreateAppImageCommand
from appimagebuilder.main.commands.run_shell_script_command import RunShellScriptCommand
from appimagebuilder.main.commands.run_test_command import RunTestCommand
from appimagebuilder.recipe.roamer import Roamer


class Orchestrator:
    """Transforms a recipe into a command list"""

    def prepare_commands(self, recipe: Roamer, args):
        if recipe.version() == 1:
            return self._prepare_commands_for_recipe_v1(args, recipe)

        return []

    def _prepare_commands_for_recipe_v1(self, args, recipe):
        commands = []
        if not args.skip_script:
            command = RunShellScriptCommand(recipe.AppDir.path(), recipe.script)
            commands.append(command)

        if not args.skip_build:
            command = CreateAppDirCommand(recipe)
            commands.append(command)

        if not args.skip_tests and recipe.AppDir.test:
            command = RunTestCommand(recipe.AppDir.path(), recipe.AppDir.test)
            commands.append(command)

        if not args.skip_appimage:
            command = CreateAppImageCommand(recipe)
            commands.append(command)

        return commands
