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
from .dynamic_loader import DynamicLoader


class Qt(BaseHelper):
    def __init__(self, app_dir, app_dir_files):
        super().__init__(app_dir, app_dir_files)

    def configure(self, app_run):
        qt_lib_path = self._get_qt_libs_path()
        if qt_lib_path:
            qt_dirs = self._get_qt_dirs(app_run)
            bin_path = app_run.env['EXEC_PATH']
            bin_path = bin_path.replace("$APPDIR", self.app_dir)
            bin_dir_path = os.path.dirname(bin_path)

            qt_conf_target_path = self._get_qt_conf_path(bin_dir_path)

            self._generate_qt_conf(qt_dirs, qt_conf_target_path)
            if qt_dirs['LibraryExecutables']:
                libexec_path = os.path.join(self.app_dir, qt_dirs['LibraryExecutables'])
                qt_dirs['Prefix'] = self._get_qt_conf_prefix_path(libexec_path)

                qt_conf_target_path = self._get_qt_conf_path(libexec_path)
                self._generate_qt_conf(qt_dirs, qt_conf_target_path)

            app_run.sections['FORCE QT WAYLAND'] = [
                'if [ "$XDG_SESSION_TYPE" == "wayland" ]; then',
                '  export QT_QPA_PLATFORM=wayland;',
                'fi',
                '',
            ]

    def _generate_qt_conf(self, qt_dirs, qt_conf_target_path):
        qt_conf = ['[Paths]\n']
        for k, v in qt_dirs.items():
            if v:
                qt_conf.append("%s=%s\n" % (k, v))

        self._write_qt_conf(qt_conf, qt_conf_target_path)

    def _write_qt_conf(self, qt_conf, qt_conf_target_path):
        logging.info("Writing qt.conf to: %s" % os.path.relpath(qt_conf_target_path, self.app_dir))
        with open(qt_conf_target_path, "w") as f:
            f.writelines(qt_conf)

    def _get_qt_dirs(self, app_run):
        bin_path = app_run.env['EXEC_PATH']
        bin_path = bin_path.replace("$APPDIR", self.app_dir)
        bin_dir_path = os.path.dirname(bin_path)

        qt_conf_target_path = self._get_qt_conf_path(bin_dir_path)
        qt_conf_dir_path = os.path.dirname(qt_conf_target_path)

        return {
            'Prefix': self._get_qt_conf_prefix_path(qt_conf_dir_path),
            'Settings': self._get_qt_conf_etc_path(qt_conf_dir_path),
            'Libraries': self._get_qt_libs_path(),
            'LibraryExecutables': self._get_qt_lib_exec_path(),
            'Plugins': self._get_qt_plugins_path(),
            'Qml2Imports': self._get_qt_qml_path(),
            'Translations': self._get_qt_translations_path(),
            'Data': self._get_qt_data_dir()
        }

    def _get_qt_libs_path(self):
        return self._get_relative_parent_dir_of('libQt5Core.so.5')

    def _get_qt_lib_exec_path(self):
        return self._get_relative_sub_dir_path('qt5/libexec')

    def _get_qt_plugins_path(self):
        return self._get_relative_sub_dir_path('qt5/plugins')

    def _get_qt_qml_path(self):
        return self._get_relative_sub_dir_path('qt5/qml')

    def _get_qt_conf_etc_path(self, qt_conf_dir_path):
        return os.path.relpath(os.path.join(self.app_dir, 'etc'), qt_conf_dir_path)

    def _get_qt_conf_prefix_path(self, qt_conf_dir_path):
        return os.path.relpath(self.app_dir, qt_conf_dir_path)

    def _get_qt_conf_path(self, bin_dir):
        full_path = os.path.join(bin_dir, "qt.conf")

        return full_path

    def _get_qt_translations_path(self):
        return self._get_relative_sub_dir_path('qt5/translations')

    def _get_qt_data_dir(self):
        return self._get_relative_sub_dir_path('share/qt5')
