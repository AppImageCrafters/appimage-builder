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

from .base_helper import BaseHelper


class FontConfig(BaseHelper):
    def __init__(self, app_dir, app_dir_files):
        super().__init__(app_dir, app_dir_files)
        self.priority = 0

    def configure(self, app_run):
        fonts_conf_path = self._get_font_conf_path()
        if fonts_conf_path in self.app_dir_files:
            app_run.env['FONTCONFIG_FILE'] = '${APPDIR}/etc/fonts/fonts.conf'
            app_run.env['FONTCONFIG_PATH'] = '${APPDIR}/usr/share/fontconfig'
            app_run.env['FONTCONFIG_SYSROOT'] = '${APPDIR}'

            self._include_app_dir_fonts_dir_in_font_conf()

    def _include_app_dir_fonts_dir_in_font_conf(self):
        data = self._read_font_conf()
        self._add_app_dir_relative_fonts_dir_line(data)
        self._write_font_conf(data)

    def _write_font_conf(self, new_lines):
        with open(self._get_font_conf_path(), 'w') as f:
            f.writelines(new_lines)

    def _add_app_dir_relative_fonts_dir_line(self, lines):
        entry_index = lines.index('<!-- Font directory list -->\n')
        lines.insert(entry_index + 1, '<dir prefix="relative">usr/share/fonts</dir>\n')

    def _read_font_conf(self):
        with open(self._get_font_conf_path(), 'r') as f:
            return f.readlines()

    def _get_font_conf_path(self):
        fonts_conf_path = os.path.join(self.app_dir, 'etc', 'fonts', 'fonts.conf')
        return fonts_conf_path
