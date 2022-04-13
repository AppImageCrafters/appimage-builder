import pathlib
import unittest

import roam

from appimagebuilder.commands import RunScriptCommand
from appimagebuilder.context import Context


class RunScriptCommandTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fake_context = Context(
            recipe_path=pathlib.Path("/tmp/non_existent/AppImageBuilder.yml"),
            build_dir=pathlib.Path("/tmp/"),
            app_dir=pathlib.Path("/tmp/AppDir"),
            app_info=None,
            bundle_info=None,
        )

    def test_set_env(self):
        script = roam.Roamer(
            [
                "export var=1",
                "if [ -z ${var+x} ]; then",
                "   exit 1; ",
                "fi",
            ]
        )

        command = RunScriptCommand(self.fake_context, script)
        command()

    def test_run_exit_1(self):
        script = roam.Roamer(["exit 1"])
        command = RunScriptCommand(self.fake_context, script)
        self.assertRaises(RuntimeError, command)

    def test_use_pass_env(self):
        script = roam.Roamer(
            [
                "if [ -z ${var+x} ]; then",
                "   exit 1; ",
                "fi",
            ]
        )
        command = RunScriptCommand(
            self.fake_context, script, env={"var": "value"}
        )
        command()

    def test_builder_env_set(self):
        script = roam.Roamer(
            [
                "echo $BUILDER_ENV",
                "if [ -z ${BUILDER_ENV+x} ]; then",
                "   exit 1; ",
                "fi",
            ]
        )
        cmd = RunScriptCommand(self.fake_context, script)
        cmd()

    def test_builder_export_variable(self):
        script_1 = roam.Roamer(["echo TEST_VAR=1 >> $BUILDER_ENV"])
        script_2 = roam.Roamer(
            [
                "if [ -z ${TEST_VAR+x} ]; then",
                "   exit 1; ",
                "fi",
            ]
        )

        cmd1 = RunScriptCommand(self.fake_context, script_1)
        cmd1()

        cmd2 = RunScriptCommand(self.fake_context, script_2)
        cmd2()

    def test_target_appdir_env_set(self):
        s = roam.Roamer(['[[ ! -z "$TARGET_APPDIR" ]] && echo $TARGET_APPDIR'])
        cmd1 = RunScriptCommand(self.fake_context, s)
        cmd1()

    def test_recipe_env_set(self):
        s = roam.Roamer(['[[ ! -z "$RECIPE" ]] && echo $RECIPE'])
        cmd1 = RunScriptCommand(self.fake_context, s)
        cmd1()

    def test_build_dir_env_set(self):
        s = roam.Roamer(['[[ ! -z "$BUILD_DIR" ]] && echo $BUILD_DIR'])
        cmd1 = RunScriptCommand(self.fake_context, s)
        cmd1()

    def test_source_dir_env_set(self):
        s = roam.Roamer(['[[ ! -z "$SOURCE_DIR" ]] && echo $SOURCE_DIR'])
        cmd1 = RunScriptCommand(self.fake_context, s)
        cmd1()


if __name__ == "__main__":
    unittest.main()
