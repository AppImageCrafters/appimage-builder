#  Copyright  2022 Alexis Lopez Zubieta
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
import pathlib

from appimagebuilder.modules.setup.environment import Environment
from appimagebuilder.utils.finder import Finder
from appimagebuilder.utils.patchelf import PatchElf, PatchElfError


class LibrariesPatcher:
    def __init__(self, appdir: pathlib.Path, env: Environment, finder: Finder = None):
        self.appdir = appdir
        self.env = env
        self.finder = finder or Finder(appdir)
        self.patchelf = PatchElf()
        self.logger = logging.getLogger("BinaryPatching")
        self.runtime_compat_dir = self.appdir / "runtime/compat"

    def patch_rpaths(self):
        libraries = self.finder.find(
            "*",
            check_true=[Finder.is_elf],
            check_false=[Finder.is_symlink],
        )

        for lib_path in libraries:
            rpaths = self._resolve_rpaths(lib_path)
            if rpaths:
                self.logger.info(lib_path.relative_to(self.appdir))
                self.logger.info("  DT_RUNPATH: %s" % ":".join(rpaths))
                self.patchelf.set_rpath(lib_path, rpaths)

    def _resolve_rpaths(self, lib_path):
        try:
            needed = self.patchelf.get_needed(lib_path)
            soname = self.patchelf.get_soname(lib_path)
            if needed and not soname:
                # libapprun_hooks.so is a runtime dependency of executables
                needed.append("libapprun_hooks.so")

            rpaths = set()
            for soname in needed:
                needed_libs = self.finder.find("**/%s" % soname)
                needed_libs_dirs = set([file.parent for file in needed_libs])
                for dir_path in needed_libs_dirs:
                    if "runtime" in dir_path.parts and "compat" in dir_path.parts:
                        rpath = dir_path.relative_to(self.runtime_compat_dir)
                    else:
                        rpath = self._rewrite_rpath_relative_to_origin(
                            dir_path, lib_path
                        )
                    rpaths.add(str(rpath))
            return rpaths
        except PatchElfError:
            pass

    def _rewrite_rpath_relative_to_origin(self, rpath, origin):
        rel_rpath = rpath.relative_to(self.appdir)
        origin_rel_path = origin.relative_to(self.appdir)
        nesting_deep = len(origin_rel_path.parts) - 1

        new_rpath = "$ORIGIN/" + "../" * nesting_deep + str(rel_rpath)
        return new_rpath
