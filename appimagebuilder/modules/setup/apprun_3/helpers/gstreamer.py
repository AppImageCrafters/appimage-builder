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
import logging
import os
import shutil
import subprocess

from .base_helper import AppRun3Helper
from ..apprun3_context import AppRun3Context


class AppRun3GStreamer(AppRun3Helper):
    def __init__(self, context: AppRun3Context):
        super().__init__(context)
        self._plugins_path = None

    def run(self):
        self._set_gst_plugins_path()
        self._set_gst_plugins_scanner_path()
        self._set_ptp_helper_path()
        self._generate_gst_registry()

    def _set_gst_plugins_path(self):
        gst_1_lib = self.context.app_dir.find_one(["*/libgstreamer-1.0.so.0"])
        if gst_1_lib:
            self._plugins_path = gst_1_lib.path.parent / "gstreamer-1.0"

            self.context.runtime_env["GST_PLUGIN_PATH"] = self._plugins_path.__str__()
            logging.info(f"GST_PLUGIN_PATH set to: {self._plugins_path}")

            self.context.runtime_env["GST_REGISTRY"] = self._plugins_path.__str__()
            logging.info(f"GST_REGISTRY set to: {self._plugins_path}")

    def _set_gst_plugins_scanner_path(self):
        gst_plugins_scanner = self.context.app_dir.find_one(["gst-plugin-scanner"])
        if gst_plugins_scanner:
            self.context.runtime_env["GST_REGISTRY_REUSE_PLUGIN_SCANNER"] = "no"
            self.context.runtime_env["GST_PLUGIN_SCANNER"] = gst_plugins_scanner.path.__str__()
            logging.info(f"GST_PLUGIN_SCANNER set to: {gst_plugins_scanner}")

    def _set_ptp_helper_path(self):
        gst_ptp_helper = self.context.app_dir.find_one(["*/gst-ptp-helper"])
        if gst_ptp_helper:
            self.context.runtime_env["GST_PTP_HELPER"] = gst_ptp_helper.path.__str__()
            logging.info(f"GST_PTP_HELPER set to: {gst_ptp_helper}")

    def _generate_gst_registry(self):
        gst_launch_bin = shutil.which("gst-launch-1.0")

        if gst_launch_bin and self._plugins_path:
            gst_registry_path = self._plugins_path / "registry.bin"
            self.context.runtime_env["GST_REGISTRY"] = gst_registry_path.__str__()

            gst_launch_env = self._prepare_gst_launch_env()
            # run gst "diagnostic" to force registry generation
            # https://gstreamer.freedesktop.org/documentation/tools/gst-launch.html?gi-language=c#diagnostic
            proc = subprocess.run(
                [gst_launch_bin, "fakesrc", "num-buffers=16", "!", "fakesink"],
                env=gst_launch_env,
            )
            if proc.returncode == 0:
                self.context.runtime_env["GST_REGISTRY_UPDATE"] = "no"
                logging.info(f"GST_REGISTRY generated at: {gst_registry_path}")
            else:
                logging.warning(f"GST_REGISTRY generation failed!")
                del self.context.runtime_env["GST_REGISTRY"]
        else:
            logging.warning(
                f"gst-launch-1.0 not found! It is required to generate gstreamer registry"
            )

    def _prepare_gst_launch_env(self):
        gst_launch_env = os.environ
        for key in self.context.runtime_env.keys():
            if key.startswith("GST"):
                gst_launch_env[key] = self.context.runtime_env[key].__str__()

        return gst_launch_env
