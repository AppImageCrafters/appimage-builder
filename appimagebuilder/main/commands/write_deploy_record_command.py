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
import os

from ruamel.yaml import YAML

from appimagebuilder.main.commands.command import Command


class WriteDeployRecordCommand(Command):
    def __init__(self, app_dir, deploy_record: dict):
        super().__init__("deploy record generation")
        self._app_dir = app_dir
        self._deploy_record = deploy_record

    def id(self):
        return "write-deploy-record"

    def __call__(self, *args, **kwargs):
        path = os.path.join(self._app_dir, ".bundle.yml")
        with open(path, "w") as f:
            logging.info(
                "Writing deploy record to: %s" % os.path.relpath(path, self._app_dir)
            )
            yaml = YAML()
            yaml.dump(self._deploy_record, f)
