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
import logging
import subprocess


def appimage_mount(target):
    abs_target_path = os.path.abspath(target)
    process = subprocess.Popen([abs_target_path, '--appimage-mount'], stdout=subprocess.PIPE)
    app_dir = process.stdout.readline().decode('utf-8').strip()
    ret_code = process.poll()

    if ret_code == None:
        logging.info("AppImage mounted at: %s" % app_dir)
        return app_dir, process
    else:
        raise RuntimeError("Unable to run: %s --appimage-mount" % target)


def appimage_umount(process):
    process.kill()
    process.wait()

    logging.info("AppImage unmounted")
