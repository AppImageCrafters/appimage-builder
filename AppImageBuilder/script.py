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


from bash import Bash
import logging


class ExecutionFailed(RuntimeError):
    pass


class Script:
    def __init__(self, recipe):
        self.instructions = recipe.get_item('script', [])

    def execute(self):
        bash = Bash()
        logger = logging.getLogger('script')
        for instruction in self.instructions:
            logger.info(" + %s" % instruction)
            command = bash.command(instruction)
            for line in command.output.splitlines():
                logger.info(" %s" % line)

            for line in command.err.splitlines():
                logger.warning(" %s" % line)

            if command.return_code != 0:
                raise ExecutionFailed("%s exited with code %s" % (instruction, command.return_code))
