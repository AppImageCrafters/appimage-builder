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

from appimagebuilder.commands.patchelf import PatchElf, PatchElfError
from appimagebuilder.common.file_test import is_elf
from .base_helper import BaseHelper


class Qt(BaseHelper):
    def __init__(self, app_dir, app_dir_files):
        super().__init__(app_dir, app_dir_files)
        self.app_dir = Path(app_dir)
        self._qt_dirs = {}

    def configure(self, app_run):
        self._locate_qt5_dirs()
        if self._qt_dirs:
            # deploy a qt.conf file next to executable files that may start a Qt application
            exec_dirs = self._find_exec_dirs()
            for path in exec_dirs:
                qt_conf = self._generate_conf(path)
                self._write_qt_conf(qt_conf, path)

    def _find_exec_dirs(self):
        exec_paths = self.app_dir_cache.find("*", attrs=["is_file", "is_exec"])
        exec_dirs = set([os.path.dirname(path) for path in exec_paths])
        exec_dirs = [Path(path) for path in exec_dirs]
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
        libqt5core_paths = self.app_dir_cache.find("*/libQt5Core.so.*")
        if libqt5core_paths:
            self._qt_dirs["Libraries"] = Path(libqt5core_paths[0]).parent

        qtwebengine_paths = self.app_dir_cache.find("*/QtWebEngineProcess")
        if qtwebengine_paths:
            self._qt_dirs["LibraryExecutables"] = Path(qtwebengine_paths[0]).parent

        qmake_paths = self.app_dir_cache.find("*/qmake")
        if qmake_paths:
            self._qt_dirs["Binaries"] = Path(qmake_paths[0]).parent

        libqminimal_paths = self.app_dir_cache.find("*/libqminimal.so")
        if libqminimal_paths:
            self._qt_dirs["Plugins"] = Path(libqminimal_paths[0]).parent.parent

        builtins_qmltypes_paths = self.app_dir_cache.find("*/builtins.qmltypes")
        if builtins_qmltypes_paths:
            self._qt_dirs["Qml2Imports"] = Path(builtins_qmltypes_paths[0]).parent

        qtbase_translations_paths = self.app_dir_cache.find("*/qtbase_en.qm")
        if qtbase_translations_paths:
            self._qt_dirs["Translations"] = Path(qtbase_translations_paths[0]).parent
