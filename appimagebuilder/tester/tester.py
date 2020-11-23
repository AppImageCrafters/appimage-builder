#   Copyright  2020 Alexis Lopez Zubieta
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#   sell copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.

#
#  Permission is hereby granted, free of charge, to any person obtaining a
#  copy of this software and associated documentation files (the "Software"),
#  to deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
import logging
import os

from appimagebuilder.tester.test_case import TestCase


class Tester:
    class TestFailed(RuntimeError):
        pass

    def __init__(self, recipe):
        self.recipe = recipe
        self.appdir = os.path.abspath(recipe.get_item("AppDir/path"))

        self.tests = []
        self._load_config()

    def _load_config(self):
        tests_path = "AppDir/test"
        tests_conf = self.recipe.get_item(tests_path, [])
        for test_name, _ in tests_conf.items():
            test_case = self._create_test_case(test_name, tests_path)
            self.tests.append(test_case)

    def _create_test_case(self, test_name, tests_path):
        image = self.recipe.get_item("%s/%s/image" % (tests_path, test_name))
        command = self.recipe.get_item("%s/%s/command" % (tests_path, test_name), "./AppRun")
        use_host_x = self.recipe.get_item("%s/%s/use_host_x" % (tests_path, test_name), False)
        env = self.recipe.get_item("%s/%s/env" % (tests_path, test_name), [])
        if isinstance(env, dict):
            env = ["%s=%s" % (k, v) for k, v in env.items()]
        test_case = TestCase(
            appdir=self.appdir,
            name=test_name,
            command=command,
            image=image,
            use_host_x=use_host_x,
            env=env
        )
        return test_case

    def run_tests(self):
        logging.info("============")
        logging.info("AppDir tests")
        logging.info("============")

        for test in self.tests:
            try:
                test.run()
            except Tester.TestFailed:
                raise
            except Exception as e:
                raise Tester.TestFailed("Execution failed. Error message: %s" % e)
