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

from appimagebuilder.utils.finder import Finder
from .base_helper import BaseHelper
from ..environment import Environment


class GStreamer(BaseHelper):
    def configure(self, env: Environment, preserve_files):
        self._set_gst_plugins_path(env)
        self._set_gst_plugins_scanner_path(env)
        self._set_ptp_helper_path(env)
        self._generate_gst_registry(env)

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

    def _generate_gst_registry(self, env):
        gst_launch_bin = shutil.which("gst-launch-1.0")
        if gst_launch_bin and "GST_PLUGIN_PATH" in env:
            env.set("GST_REGISTRY", env["GST_PLUGIN_PATH"] + "/registry.bin")

            gst_launch_env = self._prepare_gst_launch_env(env)
            # run gst "diagnostic" to force registry generation
            # https://gstreamer.freedesktop.org/documentation/tools/gst-launch.html?gi-language=c#diagnostic
            proc = subprocess.run(
                [gst_launch_bin, "fakesrc", "num-buffers=16", "!", "fakesink"],
                env=gst_launch_env,
            )
            if proc.returncode == 0:
                env.set("GST_REGISTRY_UPDATE", "no")
                logging.info(f"GST_REGISTRY generated at: {env['GST_REGISTRY']}")
            else:
                logging.warning(f"GST_REGISTRY generation failed!")
                del env["GST_REGISTRY"]
        else:
            logging.warning(
                f"gst-launch-1.0 not found! It is required to generate gstreamer registry"
            )

    def _prepare_gst_launch_env(self, env):
        gst_launch_env = os.environ
        for key in env.keys():
            if key.startswith("GST"):
                gst_launch_env[key] = env[key].__str__()

        return gst_launch_env
