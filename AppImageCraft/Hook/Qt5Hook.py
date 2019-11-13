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
import logging
import configparser

from AppImageCraft.Hook.Hook import Hook
from AppImageCraft.tools.LinkerTool import LinkerTool


class Qt5Hook(Hook):
    def __init__(self, app_dir):
        super().__init__(app_dir)
        self.logger = logging.getLogger("Qt5Hook")

    def active(self):
        return "libQt5Core.so.5" in self.app_dir.libs_registry

    def after_install(self):
        self._generate_qt_conf()

    def _generate_qt_conf(self):
        qt_conf_path = self._find_qt_conf()

        qt_conf = configparser.ConfigParser()
        qt_conf.optionxform = str

        if qt_conf_path:
            qt_conf.read(qt_conf_path)

        qt_conf['Paths']['Prefix'] = "../../usr"
        qt_conf['Paths']['Settings'] = "../../etc"

        qt_conf_target_path = self._generate_qt_conf_target_path()
        self.logger.info("Writing qt.conf to: %s" % qt_conf_target_path)
        with open(qt_conf_target_path, "w") as f:
            qt_conf.write(f)

    def _generate_qt_conf_target_path(self):
        linker_path = LinkerTool.find_binary_path(self.app_dir.path)
        liker_dir = os.path.dirname(linker_path)
        qt_conf_target_path = os.path.join(liker_dir, "qt.conf")
        return qt_conf_target_path

    def _find_qt_conf(self):
        qt_conf_path = None
        for root, dirs, files in os.walk("/usr"):
            for filename in files:
                if filename == "qt.conf":
                    qt_conf_path = os.path.join(root, filename)

        return qt_conf_path
