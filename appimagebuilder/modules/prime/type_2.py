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

#  Copyright  2020 Alexis Lopez Zubieta
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
import os
import logging
from urllib import request

from appimagebuilder.gateways.appimagetool import AppImageToolCommand
from appimagebuilder.modules.prime import common


class Type2Creator:
    def __init__(self, appdir, target_arch, update_information, sign_key, output_filename):
        self.app_dir = appdir
        self.target_arch = target_arch
        self.update_information = update_information
        self.guess_update_information = False

        if self.update_information == "None":
            self.update_information = None
        elif self.update_information == "guess":
            # appimagetool supports a param --guess, -g
            # this automatically generates the update_information based on CI
            # variables, perhaps, we should use that
            self.update_information = None
            self.guess_update_information = True

        self.sing_key = sign_key
        if self.sing_key == "None":
            self.sing_key = None

        self.target_file = output_filename

    def create(self):
        self._assert_target_architecture()

        runtime_url = self._get_runtime_url()
        runtime_path = self._get_runtime_path()
        common.download_if_required(runtime_url, runtime_path)

        self._generate_appimage(runtime_path)

    def _generate_appimage(self, runtime_path):
        appimage_tool = AppImageToolCommand(self.app_dir, self.target_file)
        appimage_tool.target_arch = self.target_arch
        appimage_tool.update_information = self.update_information
        appimage_tool.guess_update_information = self.guess_update_information
        appimage_tool.sign_key = self.sing_key
        appimage_tool.runtime_file = runtime_path
        appimage_tool.run()

    def _get_runtime_path(self):
        os.makedirs("appimage-builder-cache", exist_ok=True)
        runtime_path = "appimage-builder-cache/runtime-%s" % self.target_arch

        return runtime_path

    def _get_runtime_url(self):
        runtime_url_template = "https://github.com/AppImage/AppImageKit/releases/download/continuous/runtime-%s"
        runtime_url = runtime_url_template % self.target_arch
        return runtime_url

    def _assert_target_architecture(self):
        supported_architectures = ["i686", "aarch64", "armhf", "x86_64"]
        if self.target_arch not in supported_architectures:
            logging.error(
                "There is not a prebuild runtime for the %s architecture."
                " You will have to build the AppImage runtime manually."
                % self.target_arch
            )
