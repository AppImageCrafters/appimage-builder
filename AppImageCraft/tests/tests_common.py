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
import shutil
import tempfile

def create_echo_app_dir():
    app_dir_path = tempfile.mkdtemp()
    os.makedirs(os.path.join(app_dir_path, "usr", "bin"))
    runnable_path = os.path.join(app_dir_path, "usr", "bin", "echo")
    shutil.copy("/bin/echo", runnable_path)
    return app_dir_path, runnable_path