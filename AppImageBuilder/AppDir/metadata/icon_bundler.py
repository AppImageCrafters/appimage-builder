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
import shutil


class IconBundler:
    class Error(RuntimeError):
        pass

    def __init__(self, app_dir, icon):
        self.app_dir = app_dir
        self.icon = icon

    def bundle_icon(self):
        source_icon_path = self._get_icon_path()
        if not source_icon_path:
            raise IconBundler.Error("Unable to find any app icon named: %s" % self.icon)

        target_icon_path = os.path.join(self.app_dir, os.path.basename(source_icon_path))
        try:
            shutil.copyfile(source_icon_path, target_icon_path)
        except Exception:
            raise IconBundler.Error("Unable to copy icon from: %s to %s" % (source_icon_path, target_icon_path))

    def _get_icon_path(self):
        search_paths = [os.path.join(self.app_dir, 'usr', 'share', 'icons'),
                        os.path.join('/', 'usr', 'share', 'icons')]

        for path in search_paths:
            path = self._search_icon(path)
            if path:
                return path

        return None

    def _search_icon(self, search_path):
        logging.info("Looking app icon at: %s" % search_path)
        for root, dirs, files in os.walk(search_path):
            for filename in files:
                if self.icon in filename:
                    return os.path.join(root, filename)

        return None
