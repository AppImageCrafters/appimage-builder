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
import configparser
import os

from AppImageBuilder import tools
from AppImageBuilder.drivers import Base
from AppImageBuilder import AppDir2


class Qt(Base.Driver):
    id = 'Qt'

    def configure(self, app_dir):
        linker = tools.Linker()
        linker_path = linker.find_binary_path(app_dir.path)

        self._generate_qt_conf(app_dir)

    def _generate_qt_conf(self, app_dir):
        qt_conf_path = self._find_qt_conf()

        qt_conf = configparser.ConfigParser()
        qt_conf.optionxform = str

        if qt_conf_path:
            qt_conf.read(qt_conf_path)

        qt_conf['Paths']['Prefix'] = "../../usr"
        qt_conf['Paths']['Settings'] = "../../etc"

        qt_conf_target_path = self._generate_qt_conf_target_path(app_dir)
        self.logger().info("Writing qt.conf to: %s" % qt_conf_target_path)
        with open(qt_conf_target_path, "w") as f:
            qt_conf.write(f)

    @staticmethod
    def _generate_qt_conf_target_path(app_dir):
        linker_path = tools.Linker.find_binary_path(app_dir.path)
        liker_dir = os.path.dirname(linker_path)
        qt_conf_target_path = os.path.join(liker_dir, "qt.conf")
        return qt_conf_target_path

    @staticmethod
    def _find_qt_conf():
        qt_conf_path = None
        for root, dirs, files in os.walk("/usr"):
            for filename in files:
                if filename == "qt.conf":
                    qt_conf_path = os.path.join(root, filename)

        return qt_conf_path
