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

from AppImageBuilder import drivers


class FontConfig(drivers.Driver):
    id = 'fontconfig'

    def configure(self, app_dir):
        fonts_conf_path = app_dir.path + '/etc/fonts/fonts.conf'
        if os.path.exists(fonts_conf_path):
            app_dir.app_run.env['FONTCONFIG_FILE'] = '${APPDIR}/etc/fonts/fonts.conf'
            app_dir.app_run.env['FONTCONFIG_PATH'] = '${APPDIR}/usr/share/fontconfig'
            app_dir.app_run.env['FONTCONFIG_SYSROOT'] = '${APPDIR}'

            lines = []
            with open(fonts_conf_path, 'r') as f:
                lines.extend(f.readlines())

            new_lines = []
            for line in lines:
                new_lines.append(line)

                if '<!-- Font directory list -->' in line:
                    new_lines.append('<dir prefix="APPDIR">usr/share/fonts</dir>')

            with open(app_dir.path + '/etc/fonts/fonts.conf', 'w') as f:
                f.writelines(new_lines)
