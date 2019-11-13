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
from AppImageCraft import AppDir2


class AppImageBuilder:
    app_dir = None
    app_config = {}
    app_dir_config = {}

    def _load_app_dir(self):
        self.app_dir = AppDir2(self.app_dir_config['path'])

    def build(self):
        self._load_app_dir()
        self.app_dir.bundle_dependencies()
        self.app_dir.write_app_run(self.app_config['exec'])
