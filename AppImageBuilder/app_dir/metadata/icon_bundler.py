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
import re
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
            logging.info(
                "Setting AppDir: %s to %s" % (source_icon_path, os.path.relpath(target_icon_path, self.app_dir)))
            shutil.copyfile(source_icon_path, target_icon_path)
        except Exception:
            raise IconBundler.Error("Unable to copy icon from: %s to %s" % (source_icon_path, target_icon_path))

    def _get_icon_path(self):
        search_paths = [os.path.join(self.app_dir, 'usr', 'share', 'icons'),
                        os.path.join(self.app_dir, 'usr', 'share', 'pixmaps'),
                        os.path.join('/', 'usr', 'share', 'icons'),
                        os.path.join('/', 'usr', 'share', 'pixmaps')]

        for path in search_paths:
            path = self._search_icon(path)
            if path:
                return path

        return None

    def _search_icon(self, search_path):
        logging.info("Looking app icon at: %s" % search_path)
        path = None
        size = 0

        svg_icon_name = "%s.svg" % self.icon
        png_icon_name = "%s.png" % self.icon

        for root, dirs, files in os.walk(search_path):
            # prefer svg files over png
            if svg_icon_name in files:
                return os.path.join(root, svg_icon_name)

            if png_icon_name in files:
                new_path = os.path.join(root, png_icon_name)
                new_size = self._extract_icon_size_from_path(new_path)

                if new_size > size:
                    size = new_size
                    path = new_path

        return path

    def _extract_icon_size_from_path(self, path):
        size_search = re.search('.*/(\d+)x\d+/.*', path, re.IGNORECASE)
        if size_search:
            return int(size_search.group(1))
        else:
            logging.warning('Icon size can not be guessed from path: %s' % path)

        return 0
