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
from pathlib import Path

from appimagebuilder.utils.finder import Finder
from .base_helper import BaseHelper
from ..environment import Environment


class Qt(BaseHelper):
    def __init__(self, app_dir, app_dir_files):
        super().__init__(app_dir, app_dir_files)
        self.app_dir = Path(app_dir)
        self._qt_dirs = {}

    def configure(self, env: Environment, preserve_files):
        self._locate_qt5_dirs()
        if self._qt_dirs:
            # deploy a qt.conf file next to executable files that may start a Qt application
            exec_dirs = self._find_exec_dirs()
            for path in exec_dirs:
                qt_conf = self._generate_conf(path)
                self._write_qt_conf(qt_conf, path)

    def _find_exec_dirs(self):
        exec_dirs = self.finder.find_dirs_containing(
            file_checks=[Finder.is_file, Finder.is_executable]
        )
        return exec_dirs

    def _write_qt_conf(self, qt_conf: {str: str}, target_dir: Path):
        path = target_dir / "qt.conf"
        logging.info("Creating %s" % path.relative_to(self.app_dir))
        with path.open("w") as f:
            f.write("[Paths]\n")
            for k, v in qt_conf.items():
                f.write("%s = %s\n" % (k, v))

    def _generate_conf(self, base_path):
        config = {"Prefix": os.path.relpath(self.app_dir, base_path)}
        for k, v in self._qt_dirs.items():
            config[k] = v.relative_to(self.app_dir)

        return config

    def _locate_qt5_dirs(self):
        libqt5core_path = self.finder.find_one(
            "*/libQt5Core.so.*", [Finder.is_file, Finder.is_elf_shared_lib]
        )
        if libqt5core_path:
            self._qt_dirs["Libraries"] = libqt5core_path.parent

        qtwebengine_path = self.finder.find_one(
            "*/QtWebEngineProcess", [Finder.is_file, Finder.is_executable]
        )
        if qtwebengine_path:
            self._qt_dirs["LibraryExecutables"] = qtwebengine_path.parent

        qmake_path = self.finder.find_one(
            "*/qmake", [Finder.is_file, Finder.is_executable]
        )
        if qmake_path:
            self._qt_dirs["Binaries"] = qmake_path.parent

        libqminimal_path = self.finder.find_one(
            "*/libqminimal.so", [Finder.is_file, Finder.is_elf]
        )
        if libqminimal_path:
            self._qt_dirs["Plugins"] = libqminimal_path.parent.parent

        builtins_qmltypes_path = self.finder.find_one(
            "*/builtins.qmltypes", [Finder.is_file]
        )
        if builtins_qmltypes_path:
            self._qt_dirs["Qml2Imports"] = builtins_qmltypes_path.parent

        qtbase_translations_path = self.finder.find_one(
            "*/qt5/translations", [Finder.is_dir]
        )
        if qtbase_translations_path:
            self._qt_dirs["Translations"] = qtbase_translations_path

        data_path = self.finder.find_one("*/qt5/resources", [Finder.is_dir])
        if data_path:
            self._qt_dirs["Data"] = data_path.parent
