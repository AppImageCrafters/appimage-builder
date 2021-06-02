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

from appimagebuilder.commands.command import Command


class WriteDeployRecordCommand(Command):
    def __init__(self, context):
        super().__init__(context, "deploy record generation")

    def id(self):
        return "write-deploy-record"

    def __call__(self, *args, **kwargs):
        path = self.context.app_dir / ".bundle.yml"
        with open(path, "w") as f:
            logging.info(
                "Writing deploy record to: %s"
                % os.path.relpath(path, self.context.app_dir)
            )
            yaml = YAML()
            yaml.dump(self.context.record, f)
