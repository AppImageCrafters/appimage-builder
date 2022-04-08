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

from appimagebuilder.commands.command import Command


class Invoker:
    """Execute a given set of tasks"""

    def __init__(self):
        self.logger = logging.getLogger("main")

    def execute(self, commands: [Command] = None):
        if not commands:
            commands = []

        for command in commands:
            self.logger.info("Running %s", command.description)
            command()
