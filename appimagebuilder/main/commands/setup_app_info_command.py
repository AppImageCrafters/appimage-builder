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
from appimagebuilder.modules.setup.desktop_entry_generator import (
    DesktopEntryGenerator,
)
from appimagebuilder.modules.setup.icon_bundler import IconBundler
from appimagebuilder.generator.app_info import AppInfo
from appimagebuilder.main.commands.command import Command


class SetupAppInfoCommand(Command):
    def __init__(self, app_dir, app_info: AppInfo):
        super().__init__("desktop entry setup")
        self._app_dir = app_dir
        self._app_info = app_info

    def id(self):
        return "app-info-setup"

    def __call__(self, *args, **kwargs):
        icon_bundler = IconBundler(self._app_dir, self._app_info.icon)
        icon_bundler.bundle_icon()

        desktop_entry_generator = DesktopEntryGenerator(self._app_dir)
        desktop_entry_generator.generate(self._app_info)
