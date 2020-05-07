#!/usr/bin/env python3
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
import subprocess

from AppImageBuilder.commands.patchelf import PatchElf, PatchElfError
from AppImageBuilder.common.appimage_mount import appimage_mount, appimage_umount
from AppImageBuilder.common.file_test import is_elf
from AppImageBuilder.generator.app_runtime_analyser import AppRuntimeAnalyser


class Inspector():
    def __init__(self, target):
        self.target = target
        if os.path.isfile(self.target):
            self.app_dir, self.appimage_process = appimage_mount(target)
        else:
            self.app_dir = target
            self.appimage_process = None

    def __del__(self):
        if self.appimage_process:
            appimage_umount(self.appimage_process)

    def get_app_dir(self):
        return self.app_dir

    def get_bundle_needed_libs(self):
        libs_needed = set()
        bundle_libs = set()
        for root, dirs, files in os.walk(self.app_dir):
            if 'opt/libc' in root:
                continue

            for file in files:
                bundle_libs.add(file)
                abs_path = os.path.join(root, file)
                try:
                    if is_elf(abs_path):
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
        analyser = AppRuntimeAnalyser(self.app_dir, 'AppRun', '')
        analyser.run_app_analysis()
        return analyser.runtime_libs

    def get_dependants_of(self, lib_name):
        dependants = set()
        for root, dirs, files in os.walk(self.app_dir):
            if 'opt/libc' in root:
                continue

            for file in files:
                abs_path = os.path.join(root, file)
                try:
                    if is_elf(abs_path):
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
