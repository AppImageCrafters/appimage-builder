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
import stat


class DesktopEntryBuilder:
    app_id = ""
    app_version = ""
    app_name = ""
    app_icon = ""
    app_categories = ["Utility"]
    app_summary = ""

    template = ("[Desktop Entry]\n"
                "Type=Application\n"
                "Name=%s\n"
                "Comment=%s"
                "Exec=./AppRun\n"
                "Icon=%s\n"
                "Categories=%s;\n"
                "X-AppImage-Version=%s")

    def get_file_name(self):
        return "%s.desktop" % self.app_id

    def generate(self, path):
        f = open(path, "w")
        f.write(self.template % (self.app_name, self.app_summary, self.app_icon, ";".join(self.app_categories),
                                 self.app_version))
        f.close()
