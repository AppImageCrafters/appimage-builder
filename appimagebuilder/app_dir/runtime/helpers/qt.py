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

from appimagebuilder.commands.patchelf import PatchElf, PatchElfError
from appimagebuilder.common.file_test import is_elf
from .base_helper import BaseHelper


class Qt(BaseHelper):
    def __init__(self, app_dir, app_dir_files):
        super().__init__(app_dir, app_dir_files)

    def configure(self, app_run):
        qt_lib_path = self._get_qt_libs_path()
        if qt_lib_path:
            for path in self.app_dir_cache.find("*", attrs=["is_bin"]):
                dir_name = os.path.dirname(path)
                qt_conf_target_path = self._get_qt_conf_path(dir_name)
                if not os.path.exists(qt_conf_target_path):
                    qt_dirs = self._get_qt_dirs(dir_name)

                    self._generate_qt_conf(qt_dirs, qt_conf_target_path)

    def _generate_qt_conf(self, qt_dirs, qt_conf_target_path):
        qt_conf = ["[Paths]\n"]
        for k, v in qt_dirs.items():
            if v:
                qt_conf.append("%s=%s\n" % (k, v))

        self._write_qt_conf(qt_conf, qt_conf_target_path)

    def _write_qt_conf(self, qt_conf, qt_conf_target_path):
        logging.info(
            "Writing qt.conf to: %s"
            % os.path.relpath(qt_conf_target_path, self.app_dir)
        )
        with open(qt_conf_target_path, "w") as f:
            f.writelines(qt_conf)

    def _get_qt_dirs(self, exec_dir):
        return {
            "Prefix": self._get_qt_conf_prefix_path(exec_dir),
            "Settings": self._get_qt_conf_etc_path(exec_dir),
            "Libraries": self._get_qt_libs_path(),
            "LibraryExecutables": self._get_qt_lib_exec_path(),
            "Plugins": self._get_qt_plugins_path(),
            "Qml2Imports": self._get_qt_qml_path(),
            "Translations": self._get_qt_translations_path(),
            "Data": self._get_qt_data_dir(),
        }

    def _get_qt_libs_path(self):
        paths = self.app_dir_cache.find("*/libQt5Core.so.5")
        if paths:
            parent_dir = os.path.dirname(paths[0])
            return os.path.relpath(parent_dir, self.app_dir)

    def _get_qt_lib_exec_path(self):
        paths = self.app_dir_cache.find("*/qt5/libexec", attrs=["is_dir"])
        if paths:
            return os.path.relpath(paths[0], self.app_dir)

    def _get_qt_plugins_path(self):
        paths = self.app_dir_cache.find("*/qt5/plugins", attrs=["is_dir"])
        if paths:
            return os.path.relpath(paths[0], self.app_dir)

    def _get_qt_qml_path(self):
        paths = self.app_dir_cache.find("*/qt5/qml", attrs=["is_dir"])
        if paths:
            return os.path.relpath(paths[0], self.app_dir)

    def _get_qt_conf_etc_path(self, qt_conf_dir_path):
        return os.path.relpath(os.path.join(self.app_dir, "etc"), qt_conf_dir_path)

    def _get_qt_conf_prefix_path(self, qt_conf_dir_path):
        qt_conf_dir_path = os.path.realpath(qt_conf_dir_path)
        return os.path.relpath(self.app_dir, qt_conf_dir_path)

    def _get_qt_conf_path(self, bin_dir):
        full_path = os.path.join(bin_dir, "qt.conf")

        return full_path

    def _get_qt_translations_path(self):
        paths = self.app_dir_cache.find("*/qt5/translations", attrs=["is_dir"])
        if paths:
            return os.path.relpath(paths[0], self.app_dir)

    def _get_qt_data_dir(self):
        paths = self.app_dir_cache.find("*/share/qt5", attrs=["is_dir"])
        if paths:
            return os.path.relpath(paths[0], self.app_dir)
