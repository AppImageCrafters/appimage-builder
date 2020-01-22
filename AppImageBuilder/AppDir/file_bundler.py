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

import glob
import logging
import os
import shutil


class FileBundler:
    def __init__(self, recipe):
        self.app_dir = os.path.abspath(recipe.get_item('AppDir/path'))
        self.include_list = recipe.get_item('AppDir/files/include', [])
        self.exclude_list = recipe.get_item('AppDir/files/exclude', [])

    def bundle_included(self):
        for file in self._get_include_file_list():
            shutil.copytree(file, os.path.join(self.app_dir, file))

    def _get_include_file_list(self):
        files_list = []
        for path in self.include_list:
            files_list.extend(glob.glob(path))

        return files_list

    def remove_excluded(self):
        for path in self._get_exclude_file_list():
            if os.path.exists(path):
                if os.path.isdir(path):
                    logging.info('Excluding dir: %s' % os.path.relpath(path, self.app_dir))
                    shutil.rmtree(path)
                else:
                    logging.info('Excluding file: %s' % os.path.relpath(path, self.app_dir))
                    os.remove(path)

    def _get_exclude_file_list(self):
        files_list = []
        for path in self.exclude_list:
            full_path = os.path.join(self.app_dir, path)
            files_list.extend(glob.glob(full_path))

        return files_list
