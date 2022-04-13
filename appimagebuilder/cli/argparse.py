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
import argparse
import os


class ArgumentsParser:
    """CLI setup"""

    def __init__(self):
        self.parser = argparse.ArgumentParser(description="AppImage crafting tool")

        self.parser.add_argument(
            "--recipe",
            dest="recipe",
            default=os.path.join(os.getcwd(), "AppImageBuilder.yml"),
            help="recipe file path (default: $PWD/AppImageBuilder.yml)",
        )
        self.parser.add_argument(
            "--build-dir",
            dest="build_dir",
            default=os.path.join(os.getcwd(), "appimage-build"),
            help="Explicitly specify build directory",
        )
        self.parser.add_argument(
            "--appdir",
            dest="appdir",
            default=os.path.join(os.getcwd(), "AppDir"),
            help="Explicitly specify AppDir path",
        )
        self.parser.add_argument(
            "--log",
            dest="loglevel",
            default="INFO",
            help="logging level (default: INFO)",
        )
        self.parser.add_argument(
            "--skip-script",
            dest="skip_script",
            action="store_true",
            help="Skip script execution",
        )
        self.parser.add_argument(
            "--skip-build",
            dest="skip_build",
            action="store_true",
            help="Skip AppDir building",
        )
        self.parser.add_argument(
            "--skip-tests",
            dest="skip_tests",
            action="store_true",
            help="Skip AppDir testing",
        )
        self.parser.add_argument(
            "--skip-appimage",
            dest="skip_appimage",
            action="store_true",
            help="Skip AppImage generation",
        )
        self.parser.add_argument(
            "--generate",
            dest="generate",
            action="store_true",
            help="Try to generate recipe from an AppDir",
        )

    def parse(self):
        return self.parser.parse_args()
