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
import pathlib
import shutil

from appimagebuilder.modules.deploy import FileDeploy
from appimagebuilder.main.commands.deploy_command import DeployCommand


class FileDeployCommand(DeployCommand):
    def __init__(self, app_dir, cache_dir, deploy_record, paths, exclude):
        super().__init__("file deploy", app_dir, cache_dir, deploy_record)
        self._paths = paths
        self._exclude = exclude

    def id(self):
        return "file-deploy"

    def __call__(self, *args, **kwargs):
        helper = FileDeploy(self._app_dir)
        if self._paths:
            helper.deploy(self._paths)

        if self._exclude:
            helper.clean(self._exclude)
