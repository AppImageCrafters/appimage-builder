#   Copyright  2020 Alexis Lopez Zubieta
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#   sell copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
import os
from pathlib import Path


def make_symlink_relative(path, relative_root):
    path = Path(path)
    relative_root = Path(relative_root)

    if path.is_symlink():
        target = Path(os.readlink(path))
        if target.is_absolute():
            # workaround issue with concatenating paths using the "/" operator
            new_target = str(relative_root) + str(target)
            new_target = os.path.relpath(new_target, path.parent)

            path.unlink()
            path.symlink_to(new_target)
