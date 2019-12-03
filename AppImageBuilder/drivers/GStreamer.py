#  Copyright  2019 Alexis Lopez Zubieta
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

from AppImageBuilder import drivers


class GStreamer(drivers.Driver):
    id = 'gstreamer'

    def configure(self, app_dir):
        gst_1_lib_path = None
        gst_plugins_scanner_path = None
        gst_ptp_helper_path = None

        for root, dirs, files in os.walk(app_dir.path):
            if 'libgstreamer-1.0.so.0' in files:
                gst_1_lib_path = os.path.join(root, 'libgstreamer-1.0.so.0')

            if 'gst-plugin-scanner' in files:
                gst_plugins_scanner_path = os.path.join(root, 'gst-plugin-scanner')

            if 'gst-ptp-helper' in files:
                gst_ptp_helper_path = os.path.join(root, 'gst-ptp-helper')

        if gst_1_lib_path:
            gst_plugins_path = os.path.join(os.path.dirname(gst_1_lib_path), 'gstreamer-1.0')
            gst_plugins_path.replace(app_dir.path, '${APPDIR}')

            app_dir.app_run.env['GST_PLUGIN_PATH'] = gst_plugins_path
            app_dir.app_run.env['GST_PLUGIN_PATH_1_0'] = gst_plugins_path
            app_dir.app_run.env['GST_PLUGIN_SYSTEM_PATH'] = gst_plugins_path
            app_dir.app_run.env['GST_PLUGIN_SYSTEM_PATH_1_0'] = gst_plugins_path

            if gst_plugins_scanner_path:
                gst_plugins_scanner_path.replace(app_dir.path, '${APPDIR}')
                app_dir.app_run.env['GST_REGISTRY_REUSE_PLUGIN_SCANNER'] = 'no'
                app_dir.app_run.env['GST_PLUGIN_SCANNER_1_0'] = gst_plugins_scanner_path
            else:
                self.logger().warning('Missing gst-plugin-scanner binary')

            if gst_ptp_helper_path:
                gst_ptp_helper_path.replace(app_dir.path, '${APPDIR}')
                app_dir.app_run.env['GST_PTP_HELPER_1_0'] = gst_ptp_helper_path
            else:
                self.logger().warning('Missing gst-ptp-helper binary')