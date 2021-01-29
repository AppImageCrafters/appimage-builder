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

from appimagebuilder.common.finder import Finder
from .base_helper import BaseHelper
from ..environment import Environment


class GStreamer(BaseHelper):
    def configure(self, env: Environment):
        self._set_gst_plugins_path(env)
        self._set_gst_plugins_scanner_path(env)
        self._set_ptp_helper_path(env)

    def _set_gst_plugins_path(self, env):
        gst_1_lib_path = self.finder.find_one(
            "*/libgstreamer-1.0.so.0", [Finder.is_file, Finder.is_elf_shared_lib]
        )
        if gst_1_lib_path:
            gst_plugins_path = os.path.join(
                os.path.dirname(gst_1_lib_path), "gstreamer-1.0"
            )
            env.set("GST_PLUGIN_PATH", gst_plugins_path)
            env.set("GST_PLUGIN_SYSTEM_PATH", gst_plugins_path)

    def _set_gst_plugins_scanner_path(self, app_run):
        gst_plugins_scanner_path = self.finder.find_one(
            "gst-plugin-scanner", [Finder.is_file, Finder.is_executable]
        )
        if gst_plugins_scanner_path:
            app_run.set("GST_REGISTRY_REUSE_PLUGIN_SCANNER", "no")
            app_run.set("GST_PLUGIN_SCANNER", gst_plugins_scanner_path)

    def _set_ptp_helper_path(self, app_run):
        gst_ptp_helper_path = self.finder.find_one(
            "*/gst-ptp-helper", [Finder.is_file, Finder.is_executable]
        )
        if gst_ptp_helper_path:
            app_run.set("GST_PTP_HELPER", gst_ptp_helper_path)
