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

from AppImageBuilder.commands.appimagetool import AppImageToolCommand


class AppImageBuilder:
    def __init__(self, recipe):
        self.app_dir = recipe.get_item('AppDir/path')
        self.target_arch = recipe.get_item('AppImage/arch')
        self.app_name = recipe.get_item('AppDir/app_info/name')
        self.app_version = recipe.get_item('AppDir/app_info/version')
        self.update_information = recipe.get_item('AppImage/update-information', 'None')
        if self.update_information == 'None':
            self.update_information = None

        self.sing_key = recipe.get_item('AppImage/sign-key', 'None')
        if self.sing_key == 'None':
            self.sing_key = None

        fallback_file_name = os.path.join(os.getcwd(),
                                          '%s-%s-%s.AppImage' % (self.app_name, self.app_version, self.target_arch))
        self.target_file = recipe.get_item('AppImage/file_name', fallback_file_name)

    def build(self):
        self._assert_target_architecture()

        runtime_url = self._get_runtime_url()
        runtime_path = self._get_runtime_path()
        self._download_runtime_if_required(runtime_path, runtime_url)

        self._generate_appimage(runtime_path)

    def _generate_appimage(self, runtime_path):
        appimage_tool = AppImageToolCommand(self.app_dir, self.target_file)
        appimage_tool.target_arch = self.target_arch
        appimage_tool.update_information = self.update_information
        appimage_tool.sign_key = self.sing_key
        appimage_tool.runtime_file = runtime_path
        appimage_tool.run()

    def _download_runtime_if_required(self, runtime_path, runtime_url):
        if not os.path.exists(runtime_path):
            logging.info("Downloading runtime: %s" % runtime_url)
            request.urlretrieve(runtime_url, runtime_path)

    def _get_runtime_path(self):
        os.makedirs('appimage-builder-cache', exist_ok=True)
        runtime_path = "appimage-builder-cache/runtime-%s" % self.target_arch

        return runtime_path

    def _get_runtime_url(self):
        runtime_url_template = "https://github.com/AppImage/AppImageKit/releases/download/continuous/runtime-%s"
        runtime_url = runtime_url_template % self.target_arch
        return runtime_url

    def _assert_target_architecture(self):
        supported_architectures = ["i686", "aarch64", "armhf", "x86_64"]
        if self.target_arch not in supported_architectures:
            logging.error("There is not a prebuild runtime for the %s architecture."
                          " You will have to build the AppImage runtime manually." % self.target_arch)
