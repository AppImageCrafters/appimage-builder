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

from appimagebuilder.context import BundleInfo
from appimagebuilder.modules.generate.bundle_info_gatherer_ui import (
    BundleInfoGathererUi,
)
from appimagebuilder.modules.generate.desktop_entry_parser import DesktopEntryParser


class BundleInfoGatherer:
    """
    Gather information about a bundle from the following sources:
    - desktop entries
    - user input
    """

    _ui: BundleInfoGathererUi
    _desktop_entry_parser: DesktopEntryParser

    _bundle_info: BundleInfo

    def __init__(self, ui, desktop_entry_parser):
        self._ui = ui
        self._desktop_entry_parser = desktop_entry_parser

        self._bundle_info = BundleInfo()

    def gather_info(self, app_dir: pathlib.Path) -> BundleInfo:
        self._bundle_info = BundleInfo(app_dir=app_dir)

        # search desktop entries
        entries = self._search_desktop_entries(app_dir)

        # select main desktop entry
        if entries:
            main_entry = self._select_main_entry(entries)

            # extract application information
            self._bundle_info.app_info = self._desktop_entry_parser.parse(main_entry)

        # confirm application information
        self._confirm_application_information(self._bundle_info)

        # ask for the update information
        self._gather_update_information()

        # ask for the appimage runtime arch to be used
        self._gather_appimage_information()

        return self._bundle_info

    @staticmethod
    def _search_desktop_entries(app_dir: pathlib.Path):
        return list(app_dir.glob("**/*.desktop"))

    def _select_main_entry(self, entries):
        if not entries:
            raise RuntimeError("No desktop entries available to select")

        if len(entries) == 1:
            return entries[0]
        else:
            result = self._ui.ask_select(
                "Please select the application desktop entry", entries
            )
            return result

    def _confirm_application_information(self, bundle_info):
        app_info = bundle_info.app_info
        app_info.id = self._confirm_application_id(app_info.id)
        app_info.name = self._confirm_application_name(app_info.name)
        app_info.icon = self._confirm_application_icon(app_info.icon)
        app_info.exec = self._confirm_application_exec(
            bundle_info.app_dir, app_info.exec
        )
        app_info.exec_args = self._confirm_application_exec_args(app_info.exec_args)
        app_info.version = self._confirm_application_version(app_info.version)

    def _confirm_bundle_architecture(self):
        self._bundle_info.runtime_arch = self._ui.ask_select(
            "Architecture:",
            choices=["x86_64", "i686", "armhf", "aarch64"],
            default=self._bundle_info.runtime_arch,
        )

    def _confirm_bundle_update_information(self):
        self._bundle_info.update_string = self._ui.ask_text(
            "Update Information [Default: guess]:", default="guess"
        )

    def _confirm_application_version(self, preset):
        if not preset:
            preset = "latest"
        return self._ui.ask_text("Version [Eg: 1.0.0]:", default=preset)

    def _confirm_application_exec_args(self, preset):
        if not preset:
            preset = "$@"

        return self._ui.ask_text("Arguments [Default: $@]:", default=preset)

    def _confirm_application_exec(self, app_dir, preset):
        if preset:
            options = self._resolve_exec_path(app_dir, preset)
            if options:
                return self._ui.ask_select(
                    "Executable path:",
                    choices=options,
                )

        return self._ui.ask_text(
            "Executable path relative to AppDir [usr/bin/app]:",
            default=preset,
        )

    def _resolve_exec_path(self, app_dir: pathlib.Path, default_value):
        # search binary inside the AppDir
        matches = list(app_dir.glob("**/" + default_value))
        rel_paths = [str(match.relative_to(app_dir)) for match in matches]

        return rel_paths

    def _confirm_application_icon(self, preset):
        if not preset:
            preset = "application-vnd.appimage"

        return self._ui.ask_text("Icon:", default=preset)

    def _confirm_application_name(self, preset):
        return self._ui.ask_text("Application Name:", default=preset)

    def _confirm_application_id(self, preset):
        return self._ui.ask_text("ID [Eg: com.example.app]:", default=preset)

    def _gather_update_information(self):
        self._confirm_bundle_update_information()

    def _gather_appimage_information(self):
        self._confirm_bundle_architecture()
