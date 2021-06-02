#  Copyright  2021 Alexis Lopez Zubieta
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
from appimagebuilder.context import AppInfo
from appimagebuilder.modules.generate.desktop_entry_parser import DesktopEntryParser


class FakeDesktopEntryParser(DesktopEntryParser):
    def __init__(self, app_info: AppInfo):
        self.app_info = app_info

    def parse(self, entry_path) -> AppInfo:
        return self.app_info
