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
import fnmatch
import os


class BaseHelper:
    def __init__(self, app_dir, app_dir_files):
        self.app_dir = app_dir
        self.app_dir_files = app_dir_files

        self.priority = 0
        self.env = {}
        self.scripts = {}

    def configure(self, app_run):
        pass

    @staticmethod
    def _remove_prefix(text, prefix):
        if text.startswith(prefix):
            return text[len(prefix):]
        return text

    def _get_relative_sub_dir_path(self, sub_dir):
        for file in self.app_dir_files:
            if sub_dir in file:
                idx = file.index(sub_dir) + len(sub_dir)
                dir = file[0:idx]
                return os.path.relpath(dir, self.app_dir)

        return None

    def _get_relative_parent_dir_of(self, file_name):
        for file in self.app_dir_files:
            if file.endswith(file_name):
                dir = os.path.dirname(file)
                return os.path.relpath(dir, self.app_dir)

        return None

    def _get_relative_file_path(self, file_name):
        for file in self.app_dir_files:
            if file.endswith(file_name):
                return os.path.relpath(file, self.app_dir)

        return None

    def _get_glob_relative_sub_dir_path(self, pattern):
        for file in self.app_dir_files:
            if fnmatch.fnmatch(file, pattern):
                dir_name = os.path.dirname(file)
                return os.path.relpath(dir_name, self.app_dir)

    def _get_glob_relative_file_path(self, pattern):
        for file in self.app_dir_files:
            if fnmatch.fnmatch(file, pattern):
                return os.path.relpath(file, self.app_dir)