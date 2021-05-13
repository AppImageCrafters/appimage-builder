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
import pathlib

import questionary

from appimagebuilder.generator.appdir import AppDir
from appimagebuilder.generator.desktop_entry import DesktopEntry


def _fill_app_info(appdir):
    entry = DesktopEntry(appdir.desktop_entry)
    appdir.app_id = appdir.desktop_entry.stem
    appdir.app_name = entry.get_name()
    appdir.app_icon = entry.get_icon()
    appdir.command = [entry.get_exec()]


def __main__():
    logger = logging.getLogger("RecipeGenerator")

    appdir = AppDir(pathlib.Path.cwd() / "AppDir")
    logger.info("Inspecting AppDir: %s" % appdir.path.__str__())

    appdir.desktop_entry = _select_desktop_entry(appdir)
    _fill_app_info(appdir)


def _select_desktop_entry(appdir):
    desktop_entries = appdir.path.glob("**/*.desktop")

    desktop_entries_paths = [
        path.relative_to(appdir.path).__str__() for path in desktop_entries
    ]
    if not desktop_entries_paths:
        raise RuntimeError("Missing desktop entry, please add one")

    if len(desktop_entries_paths) == 1:
        choice = desktop_entries_paths[0]
    else:
        question = questionary.select(
            "Select the application main desktop entry:", desktop_entries_paths
        )
        choice = question.ask()

    return appdir.path / choice


if __name__ == "__main__":
    # execute only if run as the entry point into the program
    __main__()
