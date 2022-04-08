#  Copyright  2022 TheBrokenRail
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
import shutil
import subprocess

from .base_helper import BaseHelper


class MIME(BaseHelper):
    def configure(self, env, preserve_files):
        path = self.finder.base_path / "usr" / "share" / "mime"
        if path.is_dir():
            bin_path = shutil.which("update-mime-database")
            if not bin_path:
                raise RuntimeError("Missing 'update-mime-database' executable")

            subprocess.run([bin_path, path])
