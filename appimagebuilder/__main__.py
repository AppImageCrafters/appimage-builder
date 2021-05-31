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

from appimagebuilder import recipe
from appimagebuilder.cli.cli_arguments import CliArguments
from appimagebuilder.modules.generate.command_generate import CommandGenerate
from appimagebuilder.main.invoker import Invoker
from appimagebuilder.main.orchestrator import Orchestrator


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

    schema = recipe.Schema()
    schema.validate(recipe_data)

    orchestrator = Orchestrator()
    tasks = orchestrator.prepare_commands(recipe_data, args)

    invoker = Invoker()
    invoker.execute(tasks)


def _setup_logging_config(args):
    numeric_level = getattr(logging, args.loglevel.upper())
    if not isinstance(numeric_level, int):
        logging.error("Invalid log level: %s" % args.loglevel)

    logging.basicConfig(level=numeric_level)


if __name__ == "__main__":
    # execute only if run as the entry point into the program
    __main__()
