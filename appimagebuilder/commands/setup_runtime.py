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
from appimagebuilder.modules.setup.generator import RuntimeGenerator
from appimagebuilder.commands.command import Command


class SetupRuntimeCommand(Command):
    def __init__(self, context, recipe, finder):
        super().__init__(context, "runtime setup")
        self.context = context
        self._finder = finder

    def id(self):
        return "runtime-setup"

    def __call__(self, *args, **kwargs):
        runtime = RuntimeGenerator(self.context, self._finder)
        runtime.generate()
