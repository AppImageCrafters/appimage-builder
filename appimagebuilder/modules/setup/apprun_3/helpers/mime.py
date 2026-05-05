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
import shutil
import subprocess

from appimagebuilder.modules.setup.apprun_3.helpers.base_helper import AppRun3Helper


class AppRun3MIME(AppRun3Helper):
    def run(self):
        path = self.context.app_dir.path / "usr" / "share" / "mime"
        if path.is_dir():
            bin_path = shutil.which("update-mime-database")
            if not bin_path:
                raise RuntimeError("Missing 'update-mime-database' executable")

            subprocess.run([bin_path, path])

            print("Updated MIME database")
