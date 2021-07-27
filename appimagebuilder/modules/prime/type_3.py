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
import logging
import os
import pathlib
import shutil
import subprocess

from appimagebuilder.utils import shell, elf


class Type3Creator:
    def __init__(self, app_dir):
        self.logger = logging.getLogger()
        self.app_dir = pathlib.Path(app_dir).absolute()

        self.required_tool_paths = shell.resolve_commands_paths(["mksquashfs"])

    def create(self, output_filename):
        self.logger.warning(
            "Type 3 AppImages are still experimental and under development!"
        )

        squashfs_path = self._squash_appdir()

        runtime_path = self._resolve_executable()

        self._merge_parts(runtime_path, squashfs_path, output_filename)

        payload_offset = os.path.getsize(runtime_path)
        resources_offset = os.path.getsize(output_filename)

        self._fill_header(output_filename, payload_offset, resources_offset, 0)

    def _squash_appdir(self):
        squashfs_path = "./AppDir.sqfs"

        self.logger.info("Squashing AppDir")
        command = "{mksquashfs} {AppDir} {squashfs_path}".format(
            AppDir=self.app_dir, squashfs_path=squashfs_path, **self.required_tool_paths
        )
        _proc = subprocess.run(
            command,
            stderr=subprocess.PIPE,
            shell=True,
        )

        shell.assert_successful_result(_proc)
        return squashfs_path

    def _resolve_executable(self):
        launcher_arch = elf.get_arch(self.app_dir / "AppRun")
        return "/home/alexis/Workspace/AppImage/type3-runtime/cmake-build-debug/src/runtime/runtime"

    def _merge_parts(self, executable_path, squashfs_path, filename):
        shutil.copyfile(executable_path, filename)

        with open(filename, "r+b") as exec_fd:
            payload_offset = exec_fd.seek(0, 2)

            with open(squashfs_path, "rb") as sqfs_fd:
                sqfs_data = sqfs_fd.read()
                exec_fd.write(memoryview(sqfs_data))

                sqfs_fd.seek(0, 0)
                shutil.copyfileobj(sqfs_fd, exec_fd)

    def _fill_header(self, output_filename, payload_offset, resources_offset, signature_offset):
        with open(output_filename, "r+b") as f:
            f.seek(0x410, 0)
            f.write(payload_offset.to_bytes(8, 'little'))
            f.write(resources_offset.to_bytes(8, 'little'))
            f.write(signature_offset.to_bytes(8, 'little'))
