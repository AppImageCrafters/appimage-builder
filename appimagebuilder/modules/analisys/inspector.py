#!/usr/bin/env python3
#  Copyright  2021 Alexis Lopez Zubieta
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

from appimagebuilder.utils.patchelf import PatchElf, PatchElfError
from appimagebuilder.modules.analisys.appimage_mount import AppImageMount
from appimagebuilder.utils.elf import has_magic_bytes
from appimagebuilder.modules.analisys.app_runtime_analyser import AppRuntimeAnalyser


class Inspector:
    def __init__(self, target):
        self.target = target
        if os.path.isfile(self.target):
            self.appimage_mount = AppImageMount(target)
            self.app_dir = self.appimage_mount.mount()
        else:
            self.app_dir = target

    def get_app_dir(self):
        return self.app_dir

    def get_bundle_needed_libs(self):
        libs_needed = set()
        bundle_libs = set()
        for root, dirs, files in os.walk(self.app_dir):
            if "runtime/compat" in root:
                continue

            for file in files:
                bundle_libs.add(file)
                abs_path = os.path.join(root, file)
                try:
                    if has_magic_bytes(abs_path):
                        patch_elf = PatchElf()
                        patch_elf.log_stdout = False
                        patch_elf.log_stderr = False
                        patch_elf.log_command = False

                        libs_needed.update(patch_elf.get_needed(abs_path))
                except FileNotFoundError:
                    pass
                except PatchElfError:
                    pass

        bundle_needed = libs_needed - bundle_libs
        return bundle_needed

    def get_bundle_runtime_needed_libs(self):
        analyser = AppRuntimeAnalyser(self.app_dir, "AppRun", "")
        analyser.run_app_analysis()
        return analyser.runtime_libs

    def get_dependants_of(self, lib_name):
        dependants = set()
        for root, dirs, files in os.walk(self.app_dir):
            if "runtime/compat" in root:
                continue

            for file in files:
                abs_path = os.path.join(root, file)
                try:
                    if has_magic_bytes(abs_path):
                        patch_elf = PatchElf()
                        patch_elf.log_stdout = False
                        patch_elf.log_stderr = False
                        patch_elf.log_command = False

                        needs = patch_elf.get_needed(abs_path)
                        if lib_name in needs:
                            dependants.add(os.path.relpath(abs_path, self.app_dir))

                except FileNotFoundError:
                    pass
                except PatchElfError:
                    pass

        return dependants
