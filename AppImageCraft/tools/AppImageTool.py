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


import logging
import subprocess


class AppImageTool:
    def bundle(self, app_dir_path, target_dir_path):
        logging.info("Generating AppImage from %s" % app_dir_path)
        result = subprocess.run(["appimagetool", app_dir_path, target_dir_path])
        if result.returncode != 0:
            logging.error("AppImage generation failed")
        else:
            logging.info(result.stdout)
            logging.info("AppImage created successfully")
