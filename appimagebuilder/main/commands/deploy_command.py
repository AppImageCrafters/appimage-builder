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
from appimagebuilder.main.commands.command import Command


class DeployCommand(Command):
    """
    Command used to deploy files into the AppDir

    Thees command must log the deployed files their sources into the deploy record.
    """

    def __init__(self, description, app_dir, cache_dir, deploy_record):
        super().__init__(description)
        self._app_dir = app_dir
        self._cache_dir = cache_dir
        self._deploy_record = deploy_record
