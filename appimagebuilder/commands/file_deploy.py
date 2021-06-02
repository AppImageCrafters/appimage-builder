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
from appimagebuilder.commands import Command
from appimagebuilder.context import Context
from appimagebuilder.modules.deploy import FileDeploy


class FileDeployCommand(Command):
    def __init__(self, context: Context, paths, exclude):
        super().__init__(context, "file deploy")
        self._paths = paths
        self._exclude = exclude

    def id(self):
        return "file-deploy"

    def __call__(self, *args, **kwargs):
        helper = FileDeploy(str(self.context.app_dir))
        if self._paths:
            helper.deploy(self._paths)

        if self._exclude:
            helper.clean(self._exclude)
