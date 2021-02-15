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

from unittest import TestCase

from appimagebuilder.common import shell


class TestShell(TestCase):
    def test_run_set_env(self):
        shell.execute(
            [
                "export var=1",
                "if [ -z ${var+x} ]; then",
                "   exit 1; ",
                "fi",
            ]
        )

    def test_run_exit_1(self):
        self.assertRaises(
            RuntimeError,
            shell.execute,
            [
                "exit 1",
            ],
        )

    def test_use_pass_env(self):
        shell.execute(
            [
                "if [ -z ${var+x} ]; then",
                "   exit 1; ",
                "fi",
            ],
            env={"var": "value"},
        )

    def test_builder_env_set(self):
        shell.execute(
            [
                "echo $BUILDER_ENV",
                "if [ -z ${BUILDER_ENV+x} ]; then",
                "   exit 1; ",
                "fi",
            ]
        )

    def test_builder_export_variable(self):
        shell.execute("echo TEST_VAR=1 >> $BUILDER_ENV")
        shell.execute(
            [
                "if [ -z ${TEST_VAR+x} ]; then",
                "   exit 1; ",
                "fi",
            ]
        )
