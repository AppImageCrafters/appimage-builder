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

        add_gstreamer_env = False
        for root, dirs, files in os.walk(app_dir.path):
            if 'libgstreamer-1.0.so.0' in files:
                add_gstreamer_env = True
                break

        if add_gstreamer_env:
            app_dir.app_run.env['GST_REGISTRY_REUSE_PLUGIN_SCANNER'] = 'no'
            app_dir.app_run.env['GST_PLUGIN_PATH_1_0'] = '${APPDIR}/usr/lib/x86_64-linux-gnu/gstreamer-1.0/'
            app_dir.app_run.env['GST_PLUGIN_SYSTEM_PATH_1_0'] = '${APPDIR}/usr/lib/x86_64-linux-gnu/gstreamer-1.0/'
            app_dir.app_run.env['GST_PLUGIN_SCANNER_1_0'] = '{APPDIR}/usr/lib/x86_64-linux-gnu/gstreamer1.0/' \
                                                            'gstreamer-1.0/gst-plugin-scanner'
            app_dir.app_run.env['GST_PTP_HELPER_1_0'] = '${APPDIR}/usr/lib/x86_64-linux-gnu/' \
                                                        'gstreamer1.0/gstreamer-1.0/gst-ptp-helper'
