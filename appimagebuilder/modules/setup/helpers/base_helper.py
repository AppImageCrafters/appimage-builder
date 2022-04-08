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

from appimagebuilder.utils.finder import Finder


class BaseHelper:
    def __init__(self, app_dir, finder: Finder):
        self.app_dir = app_dir
        self.finder = finder

        self.priority = 0
        self.env = {}
        self.scripts = {}

    def configure(self, env, preserve_files):
        pass

    @staticmethod
    def _remove_prefix(text, prefix):
        if text.startswith(prefix):
            return text[len(prefix) :]
        return text
