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

from .command import Command
from appimagebuilder.recipe.roamer import Roamer
from appimagebuilder.modules.test import ExecutionTest, TestFailed
from ..context import Context


class RunTestCommand(Command):
    def __init__(self, context: Context, tests_settings: Roamer):
        super().__init__(context, "AppDir tests")
        self.app_dir = context.app_dir
        self.tests_settings = tests_settings

    def id(self):
        return "test"

    def __call__(self, *args, **kwargs):
        test_cases = self._load_tests(self.tests_settings())
        try:
            for test in test_cases:
                test.run()
        except TestFailed as err:
            logging.error("test failed")
            logging.error(err)

            exit(1)

    def _load_tests(self, test_settings: {}):
        test_cases = []

        for name, data in test_settings.items():
            data_accessor = Roamer(data)
            env = data_accessor.env() or []
            if isinstance(env, dict):
                env = ["%s=%s" % (k, v) for k, v in env.items()]

            test = ExecutionTest(appdir=self.app_dir, name=name, image=data_accessor.image(),
                                 command=data_accessor.command(), env=env)
            test_cases.append(test)

        return test_cases
