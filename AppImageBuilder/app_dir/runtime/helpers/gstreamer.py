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

from .base_helper import BaseHelper


class GStreamer(BaseHelper):
    def configure(self, app_run):
        self._set_gst_plugins_path(app_run)
        self._set_gst_plugins_scanner_path(app_run)
        self._set_ptp_helper_path(app_run)

    def _set_gst_plugins_path(self, app_run):
        gst_1_lib_path = self._get_gst_1_lib_path()
        gst_plugins_path = self._get_gst_plugins_path(gst_1_lib_path)
        if gst_1_lib_path:
            app_run.env['GST_PLUGIN_PATH'] = '${APPDIR}/%s' % gst_plugins_path
            # app_run.env['GST_PLUGIN_PATH_1_0'] = '${APPDIR}/%s' % gst_plugins_path
            app_run.env['GST_PLUGIN_SYSTEM_PATH'] = '${APPDIR}/%s' % gst_plugins_path
            # app_run.env['GST_PLUGIN_SYSTEM_PATH_1_0'] = '${APPDIR}/%s' % gst_plugins_path

    def _set_gst_plugins_scanner_path(self, app_run):
        gst_plugins_scanner_path = self._get_gst_plugins_scanner_path()
        if gst_plugins_scanner_path:
            app_run.env['GST_REGISTRY_REUSE_PLUGIN_SCANNER'] = 'no'
            app_run.env['GST_PLUGIN_SCANNER'] = '${APPDIR}/%s' % gst_plugins_scanner_path
            # app_run.env['GST_PLUGIN_SCANNER_1_0'] = '${APPDIR}/%s' % gst_plugins_scanner_path

    def _set_ptp_helper_path(self, app_run):
        gst_ptp_helper_path = self._get_gst_ptp_helper_path()
        if gst_ptp_helper_path:
            app_run.env['GST_PTP_HELPER'] = '${APPDIR}/%s' % gst_ptp_helper_path
            # app_run.env['GST_PTP_HELPER_1_0'] = '${APPDIR}/%s' % gst_ptp_helper_path

    def _get_gst_1_lib_path(self):
        return self._get_relative_file_path('libgstreamer-1.0.so.0')

    def _get_gst_plugins_path(self, gst_1_lib_path):
        if gst_1_lib_path:
            return os.path.join(os.path.dirname(gst_1_lib_path), 'gstreamer-1.0')

        return None

    def _get_gst_plugins_scanner_path(self):
        return self._get_relative_file_path('gst-plugin-scanner')

    def _get_gst_ptp_helper_path(self):
        return self._get_relative_file_path('gst-ptp-helper')
