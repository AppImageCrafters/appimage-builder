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

from AppImageCraft.Hook.Hook import Hook


class FontConfigHook(Hook):
    def active(self):
        return "libfontconfig.so.1" in self.app_dir.libs_registry

    def app_run_commands(self):
        return "# Set font config configuration file\n" \
               "export FONTCONFIG_FILE=\"${APPDIR}/etc/fonts/fonts.conf\"\n"
