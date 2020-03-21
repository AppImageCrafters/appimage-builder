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

import unittest

from .gstreamer import GStreamer


class GStreamerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.gst = GStreamer('/AppDir',
                             ['/AppDir/usr/lib/x86_64-linux-gnu/libgstreamer-1.0.so.0',
                              '/AppDir/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-plugin-scanner',
                              '/AppDir/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper'
                              ])

    def test_get_gst_1_lib_path(self):
        self.assertEqual(self.gst._get_gst_1_lib_path(), 'usr/lib/x86_64-linux-gnu/libgstreamer-1.0.so.0')

    def test_get_gst_plugins_path(self):
        self.assertEqual(self.gst._get_gst_plugins_path('usr/lib/x86_64-linux-gnu/libgstreamer-1.0.so.0'),
                         'usr/lib/x86_64-linux-gnu/gstreamer-1.0')

    def test_get_gst_plugins_scanner_path(self):
        self.assertEqual(self.gst._get_gst_plugins_scanner_path(),
                         'usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-plugin-scanner')

    def test_get_gst_ptp_helper_path(self):
        self.assertEqual(self.gst._get_gst_ptp_helper_path(),
                         'usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper')


if __name__ == '__main__':
    unittest.main()
