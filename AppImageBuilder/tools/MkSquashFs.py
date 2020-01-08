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

import os
import stat

import logging
import subprocess

class MkSquashFs:
    def make_squash_file_system(self, source_dir, destination_file):
        result = subprocess.run(["mksquashfs", source_dir, destination_file, "-no-xattrs"])
        if result.returncode != 0:
            logging.error("Squash file system generation failed")
        else:
            logging.info(result.stdout)
            logging.info("Squash file system created successfully")
