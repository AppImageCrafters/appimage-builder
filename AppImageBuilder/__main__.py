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

import argparse
import logging
import os

from AppImageBuilder.appimage_builder import AppImageBuilder
from AppImageBuilder.app_dir.builder import Builder
from AppImageBuilder.app_dir.tester import Tester
from AppImageBuilder.recipe import Recipe
from AppImageBuilder.script import Script


def __main__():
    parser = argparse.ArgumentParser(description='AppImage crafting tool')
    parser.add_argument('--recipe', dest='recipe', default=os.path.join(os.getcwd(), "AppImageBuilder.yml"),
                        help='recipe file path (default: $PWD/AppImageBuilder.yml)')
    parser.add_argument('--log', dest='loglevel', default="INFO",
                        help='logging level (default: INFO)')
    parser.add_argument('--skip-script', dest='skip_script', action="store_true",
                        help='Skip script execution')
    parser.add_argument('--skip-build', dest='skip_build', action="store_true",
                        help='Skip AppDir building')
    parser.add_argument('--skip-tests', dest='skip_tests', action="store_true",
                        help='Skip AppDir testing')
    parser.add_argument('--skip-appimage', dest='skip_appimage', action="store_true",
                        help='Skip AppImage generation')

    args = parser.parse_args()
    numeric_level = getattr(logging, args.loglevel.upper())
    if not isinstance(numeric_level, int):
        logging.error('Invalid log level: %s' % args.loglevel)
    logging.basicConfig(level=numeric_level)

    recipe = Recipe()
    recipe.load_file(args.recipe)
    if not args.skip_script:
        script = Script(recipe)
        script.execute()

    if not args.skip_build:
        builder = Builder(recipe)
        builder.build()

    if not args.skip_tests:
        tester = Tester(recipe)
        tester.run_tests()

    if not args.skip_appimage:
        builder = AppImageBuilder(recipe)
        builder.build()


if __name__ == '__main__':
    # execute only if run as the entry point into the program
    __main__()
