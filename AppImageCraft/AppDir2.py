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


class AppDir2:
    path = None
    deploy_cache = []

    def __init__(self, path):
        os.makedirs(path, exist_ok=True)
        self.path = path

    def files(self):
        file_list = []

        for root, dirs, files in os.walk(self.path):
            file_list.extend([os.path.join(root, file_name) for file_name in files])

        return file_list

    def bundled(self, source):
        return os.path.exists(self.path + source) or source.startswith(self.path)
