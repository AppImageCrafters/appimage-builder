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
from appimagebuilder.modules.prime.type_2 import Type2Creator
from appimagebuilder.commands.command import Command
from appimagebuilder.modules.prime.type_3 import Type3Creator
from appimagebuilder.recipe.roamer import Roamer


class CreateAppImageCommand(Command):
    def __init__(self, context, recipe: Roamer):
        super().__init__(context, "AppImage creation")
        self.recipe = recipe

    def id(self):
        super().id()

    def __call__(self, *args, **kwargs):
        appimage_format = self.recipe.AppImage.format() or 2
        self.app_dir = self.recipe.AppDir.path()

        if appimage_format == 2:
            self._create_type_2_appimage()
            return

        if appimage_format == 3:
            self._create_type_3_appimage()
            return

        raise RuntimeError(f"Unknown AppImage format {appimage_format}")

    def _create_type_2_appimage(self):

        target_arch = self.recipe.AppImage.arch()
        app_name = self.recipe.AppDir.app_info.name()
        app_version = self.recipe.AppDir.app_info.version()
        update_information = self.recipe.AppImage["update-information"]() or "None"
        file_name = self.recipe.AppDir.app_info.file_name()
        sign_key = self.recipe.AppImage["sign-key"] or "None"
        if sign_key == "None":
            sign_key = None
        creator = Type2Creator(
            self.app_dir,
            app_name,
            app_version,
            target_arch,
            update_information,
            sign_key,
            file_name,
        )
        creator.create()

    def _create_type_3_appimage(self):
        creator = Type3Creator(self.app_dir)
        creator.create()
