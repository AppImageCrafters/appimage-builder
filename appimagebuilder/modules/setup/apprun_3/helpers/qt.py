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
from .base_helper import AppRun3Helper
from ..apprun3_context import AppRun3Context


class AppRun3QtSetup(AppRun3Helper):
    def __init__(self, context: AppRun3Context):
        super().__init__(context)

        self._qt5_dirs = {}
        self._qt6_dirs = {}

    def run(self):
        self._configure_qt5()
        self._configure_qt6()

    def _configure_qt5(self):
        self._locate_qt5_dirs()
        if self._qt5_dirs:
            # deploy a qt.conf file next to executable files that may start a Qt application
            exec_dirs = self._find_exec_dirs()
            for path in exec_dirs:
                qt_conf = self._generate_conf(path, self._qt5_dirs)
                self._write_qt_conf(qt_conf, path)

    def _find_exec_dirs(self):
        exec_dirs = set([entry.path.parent for entry in self.context.app_dir.files.values() if entry.is_executable])

        return exec_dirs

    def _write_qt6_conf(self, qt_conf: {str: str}, target_dir: Path):
        path = target_dir / "qt6.conf"
        logging.info("Creating %s" % path.relative_to(self.context.app_dir.path))
        with path.open("w") as f:
            f.write("[Paths]\n")
            for k, v in qt_conf.items():
                f.write("%s = %s\n" % (k, v))

    def _write_qt_conf(self, qt_conf: {str: str}, target_dir: Path):
        path = target_dir / "qt.conf"
        logging.info("Creating %s" % path.relative_to(self.context.app_dir.path))
        with path.open("w") as f:
            f.write("[Paths]\n")
            for k, v in qt_conf.items():
                f.write("%s = %s\n" % (k, v))

    def _generate_conf(self, base_path, content: dict):
        config = {"Prefix": os.path.relpath(self.context.app_dir.path, base_path)}
        for k, v in content.items():
            config[k] = v.relative_to(self.context.app_dir.path)

        return config

    def _locate_qt5_dirs(self):
        libqt5core = self.context.app_dir.find_one(["*/libQt5Core.so.*"])
        if libqt5core:
            self._qt5_dirs["Libraries"] = libqt5core.path.parent
        else:
            # don't go any forward if libQt5Core is not found
            return

        qtwebengine = self.context.app_dir.find_one(["*/QtWebEngineProcess"])
        if qtwebengine:
            self._qt5_dirs["LibraryExecutables"] = qtwebengine.path.parent

        qmake = self.context.app_dir.find_one(["*/qmake"])
        if qmake:
            self._qt5_dirs["Binaries"] = qmake.path.parent

        libqminimal = self.context.app_dir.find_one(["*/libqminimal.so"])
        if libqminimal:
            self._qt5_dirs["Plugins"] = libqminimal.path.parent.parent

        builtins_qmltypes = self.context.app_dir.find_one(["*/builtins.qmltypes"])
        if builtins_qmltypes:
            self._qt5_dirs["Qml2Imports"] = builtins_qmltypes.path.parent

        qtbase_translations = self.context.app_dir.find_one(["*/qt5/translations/*"])
        if qtbase_translations:
            self._qt5_dirs["Translations"] = qtbase_translations.path.parent

        data = self.context.app_dir.find_one(["*/qt5/resources/*"])
        if data:
            self._qt5_dirs["Data"] = data.path.parent

    def _configure_qt6(self):
        # https://doc.qt.io/qt-6/qt-conf.html
        self._locate_qt6_dirs()
        if self._qt6_dirs:
            # deploy a qt.conf file next to executable files that may start a Qt application
            exec_dirs = self._find_exec_dirs()
            for path in exec_dirs:
                qt_conf = self._generate_conf(path, self._qt6_dirs)
                self._write_qt6_conf(qt_conf, path)

    def _locate_qt6_dirs(self):
        libqt6core = self.context.app_dir.find_one(["*/libQt6Core.so.*"])
        if libqt6core:
            self._qt6_dirs["Libraries"] = libqt6core.path.parent
        else:
            # don't go any forward if libQt6Core is not found
            return

        qtwebengine = self.context.app_dir.find_one(["*/QtWebEngineProcess"])
        if qtwebengine:
            self._qt6_dirs["LibraryExecutables"] = qtwebengine.path.parent

        qmake = self.context.app_dir.find_one(["*/qmake6"])
        if qmake:
            self._qt6_dirs["Binaries"] = qmake.path.parent

        libqminimal = self.context.app_dir.find_one(["*/libqminimal.so"])
        if libqminimal:
            self._qt6_dirs["Plugins"] = libqminimal.path.parent.parent

        builtins_qmltypes = self.context.app_dir.find_one(["*/builtins.qmltypes"])
        if builtins_qmltypes:
            self._qt6_dirs["QmlImports"] = builtins_qmltypes.path.parent
            self._qt6_dirs["Qml2Imports"] = builtins_qmltypes.path.parent

        qtbase_translations = self.context.app_dir.find_one(["*/qt6/translations/*"])
        if qtbase_translations:
            self._qt6_dirs["Translations"] = qtbase_translations.path.parent

        data = self.context.app_dir.find_one(["*/qt6/resources/*"])
        if data:
            self._qt6_dirs["Data"] = data.path.parent.parent
