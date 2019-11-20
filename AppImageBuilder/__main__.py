#!/usr/bin/env python3
#  Copyright  2019 Alexis Lopez Zubieta
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

import os
import logging
import argparse

from AppImageBuilder.Configurator import ConfigurationError
from AppImageBuilder.Configurator import Configurator


def __main__():
    parser = argparse.ArgumentParser(description='AppImage crafting tool')
    parser.add_argument('--recipe', dest='recipe', default=os.path.join(os.getcwd(), "AppImageBuilder.yml"),
                        help='recipe file path (default: $PWD/AppImageBuilder.yml)')
    parser.add_argument('--log', dest='loglevel', default="INFO",
                        help='logging level (default: INFO)')
    parser.add_argument('--skip-script', dest='skip_script', action="store_true",
                        help='Skip script execution')
    parser.add_argument('--skip-appdir', dest='skip_appdir', action="store_true",
                        help='Skip AppDir building')
    parser.add_argument('--skip-appdir-test', dest='skip_appdir_test', action="store_true",
                        help='Skip AppDir testing')
    parser.add_argument('--skip-appimage', dest='skip_appimage', action="store_true",
                        help='Skip AppImage generation')

    args = parser.parse_args()
    _configure_logger(args)

    try:
        configurator = Configurator()
        builder = configurator.load_file(args.recipe)
        if not args.skip_script:
            builder.run_script()

        if not args.skip_appdir:
            builder.build_app_dir()

        if not args.skip_appdir_test:
            builder.test_app_dir()

        if not args.skip_appimage:
            builder.build_appimage()

    except ConfigurationError as error:
        logging.error(error)


def _configure_logger(args):
    numeric_level = getattr(logging, args.loglevel.upper())
    if not isinstance(numeric_level, int):
        logging.error('Invalid log level: %s' % args.loglevel)
    logging.basicConfig(level=numeric_level)


if __name__ == '__main__':
    # execute only if run as the entry point into the program
    __main__()
