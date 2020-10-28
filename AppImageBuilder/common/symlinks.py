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


def make_symlinks_relative(file):
    if os.path.islink(file):
        link_target = os.readlink(file)
        if os.path.isabs(link_target):
            os.unlink(file)

            new_link_target = os.path.relpath(
                link_target, os.path.join("/", os.path.dirname(file))
            )
            logging.info(
                "Fixing symlink %s target: from %s to %s"
                % (file, link_target, new_link_target)
            )
            os.symlink(new_link_target, file)
