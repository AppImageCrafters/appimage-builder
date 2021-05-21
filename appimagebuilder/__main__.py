#!/usr/bin/env python3
#  Copyright  2020 Alexis Lopez Zubieta
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

import roam

from appimagebuilder import recipe
from appimagebuilder.appimage import AppImageCreator
from appimagebuilder.builder.builder import Builder
from appimagebuilder.cli.cli_arguments import CliArguments
from appimagebuilder.common import shell
from appimagebuilder.generator.command_generate import CommandGenerate
from appimagebuilder.tester import ExecutionTest
from appimagebuilder.tester.errors import TestFailed


def __main__():
    cli_arguments = CliArguments()
    args = cli_arguments.parse()

    _setup_logging_config(args)

    if args.generate:
        generator = CommandGenerate()
        generator.generate()
        exit(0)

    recipe_loader = recipe.Loader()
    recipe_data = recipe_loader.load(args.recipe)

    if recipe_data.version() == 1:
        recipe_schema = recipe.Schema()
        recipe_schema.v1.validate(recipe_data())

        if not args.skip_script:
            script_instructions = recipe_data.script()
            logging.info("======")
            logging.info("Script")
            logging.info("======")
            appdir = recipe_data.AppDir.path()
            shell.execute(script_instructions, env={"APPDIR": os.path.abspath(appdir)})

        if not args.skip_build:
            creator = Builder(recipe_data)
            creator.build()

        if not args.skip_tests:
            if recipe_data.AppDir.test():
                logging.info("============")
                logging.info("AppDir tests")
                logging.info("============")

                test_cases = _load_tests(recipe_data)
                try:
                    for test in test_cases:
                        test.run()
                except TestFailed as err:
                    logging.error("Tests failed")
                    logging.error(err)

                    exit(1)

        if not args.skip_appimage:
            creator = AppImageCreator(recipe_data)
            creator.create()
    else:
        logging.error("Unknown recipe version: %s" % recipe_data.version())
        logging.info(
            "Please make sure you're using the latest appimage-builder version"
        )
        exit(1)


def _setup_logging_config(args):
    numeric_level = getattr(logging, args.loglevel.upper())
    if not isinstance(numeric_level, int):
        logging.error("Invalid log level: %s" % args.loglevel)

    logging.basicConfig(level=numeric_level)


def _load_tests(recipe_data):
    test_cases = []

    appdir = recipe_data.AppDir.path() or "AppDir"
    appdir = os.path.abspath(appdir)

    for name, data in recipe_data.AppDir.test().items():
        data_accessor = roam.Roamer(data)
        env = data_accessor.env() or []
        if isinstance(env, dict):
            env = ["%s=%s" % (k, v) for k, v in env.items()]

        test = ExecutionTest(
            appdir=appdir,
            name=name,
            image=data_accessor.image(),
            command=data_accessor.command(),
            use_host_x=data_accessor.use_host_x(),
            env=env,
        )
        test_cases.append(test)

    return test_cases


if __name__ == "__main__":
    # execute only if run as the entry point into the program
    __main__()
