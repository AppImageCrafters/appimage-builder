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

from appimagebuilder.modules.setup.apprun_3.helpers.base_helper import AppRun3Helper


class AppRun3Python(AppRun3Helper):
    def run(self):
        python_bin = self.context.app_dir.find_one(["*/bin/python2*", "*/bin/python3*"])
        if python_bin:
            logging.info("Found python binary: %s", python_bin.path)
            python_home = python_bin.path.parent.parent
            self.context.runtime_env["PYTHONHOME"] = str(python_home)
            logging.info("Setting PYTHONHOME to: %s", python_home)

        python_site_package = self.context.app_dir.find_one(["*/python*/site-packages/*/*"])
        if python_site_package:
            python_path = python_site_package.path.parent.parent
            self.context.runtime_env["PYTHONPATH"] = str(python_path)
            logging.info("Setting PYTHONPATH to: %s", python_path)
