#!/usr/bin/env python3
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

import argparse
import logging
from pathlib import Path

from appimagebuilder.tester import ExecutionTest
from appimagebuilder.tester.dependencies_test import DependenciesTest


def configure_logging(args):
    numeric_level = getattr(logging, args.loglevel.upper())
    if not isinstance(numeric_level, int):
        logging.error("Invalid log level: %s" % args.loglevel)
    logging.basicConfig(level=numeric_level)


def __main__():
    parser = argparse.ArgumentParser(description="AppDir testing tool")
    parser.add_argument("target", help="AppDir to be tested")
    parser.add_argument(
        "--log", dest="loglevel", default="INFO", help="logging level (default: INFO)"
    )
    parser.add_argument(
        "--docker-images",
        metavar="DOCKER_IMAGE",
        dest="docker_images",
        type=str,
        nargs="+",
        required=True,
        help="Docker images to test on",
    )

    parser.add_argument(
        "--test",
        dest="do_test",
        action="store_true",
        help="Test running the target on given docker images",
    )

    parser.add_argument(
        "--static-test",
        dest="do_static_test",
        action="store_true",
        help="Test running the target on given docker images",
    )

    args = parser.parse_args()
    configure_logging(args)

    target = Path(args.target).absolute()
    for docker_image in args.docker_images:
        try:
            if args.do_test:
                test = ExecutionTest(
                    appdir=target,
                    name=docker_image,
                    image=docker_image,
                    command="./AppRun",
                    use_host_x=True,
                )
                test.run()

            if args.do_static_test:
                test = DependenciesTest(target, docker_image)
                test.run()

        except Exception as e:
            logging.error("Tests failed. %s" % e)


if __name__ == "__main__":
    __main__()
