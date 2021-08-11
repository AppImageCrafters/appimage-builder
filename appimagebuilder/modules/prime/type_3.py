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
import subprocess
import tempfile

import bson

from appimagebuilder.modules.prime import common
from appimagebuilder.utils import file_utils
from appimagebuilder.utils import shell, elf


class Type3Creator:
    def __init__(self, app_dir, cache_dir="appimage-builder-cache"):
        self.logger = logging.getLogger()
        self.app_dir = pathlib.Path(app_dir).absolute()
        self.cache_dir = pathlib.Path(cache_dir)
        self.runtime_project_url = (
            "https://github.com/AppImageCrafters/appimage-runtime"
        )

        self.required_tool_paths = shell.resolve_commands_paths(["mksquashfs", "gpg"])

    def create(self, output_filename, metadata=None, gnupg_keys=None):
        if metadata is None:
            metadata = {}

        if gnupg_keys is None:
            gnupg_keys = []

        self.logger.warning(
            "Type 3 AppImages are still experimental and under development!"
        )

        squashfs_path = self._squash_appdir()

        runtime_path = self._resolve_executable()

        file_utils.extend_file(runtime_path, squashfs_path, output_filename)

        payload_offset = os.path.getsize(runtime_path)
        metadata_offset = os.path.getsize(output_filename)
        self._append_metadata(output_filename, metadata)
        signatures_offset = os.path.getsize(output_filename)
        self._fill_header(
            output_filename, payload_offset, metadata_offset, signatures_offset
        )

        self._sign_bundle(output_filename, gnupg_keys, signatures_offset)
        # remove squashfs
        squashfs_path.unlink()

    def _squash_appdir(self):
        squashfs_path = self.cache_dir / "AppDir.sqfs"

        self.logger.info("Squashing AppDir")
        command = "{mksquashfs} {AppDir} {squashfs_path} -reproducible".format(
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
        url = self._get_runtime_url(launcher_arch)
        path = self._get_runtime_path(launcher_arch)
        common.download_if_required(url, path.__str__())

        return path

    def _fill_header(
        self, output_filename, payload_offset, metadata_offset, signature_offset
    ):
        with open(output_filename, "r+b") as f:
            f.seek(0x410, 0)
            f.write(payload_offset.to_bytes(8, "little"))
            f.write(metadata_offset.to_bytes(8, "little"))
            f.write(signature_offset.to_bytes(8, "little"))

    def _get_runtime_path(self, arch):
        self.cache_dir.parent.mkdir(parents=True, exist_ok=True)
        runtime_path = self.cache_dir / f"runtime-{arch}"

        return runtime_path

    def _get_runtime_url(self, arch):
        runtime_url_template = (
            self.runtime_project_url
            + "/releases/download/continuous/runtime-Release-%s"
        )
        runtime_url = runtime_url_template % arch
        return runtime_url

    def _append_metadata(self, output_filename, metadata):
        raw = bson.dumps(metadata)

        with open(output_filename, "r+b") as fd:
            fd.seek(0, 2)
            fd.write(raw)

    def _sign_bundle(self, output_filename, gnupg_keys, signatures_offset):
        signatures = []

        for keyid in gnupg_keys:
            signature = self._generate_bundle_signature_using_gpg(
                keyid, output_filename, signatures_offset
            )
            signatures.append(
                {
                    "method": "gpg",
                    "keyid": keyid,
                    "data": signature,
                }
            )

        encoded_signatures = bson.dumps({"signatures": signatures})
        with open(output_filename, "r+b") as fd:
            fd.seek(signatures_offset, 0)
            fd.write(encoded_signatures)

    def _generate_bundle_signature_using_gpg(self, keyid, filename, limit):
        # file chunks will be written here
        input_path = tempfile.NamedTemporaryFile().name
        os.mkfifo(input_path)

        # sign the file with out including the signatures section
        output_path = tempfile.NamedTemporaryFile().name

        # call gpg
        args = [
            self.required_tool_paths["gpg"],
            "--detach-sign",
            "--armor",
            "--default-key",
            keyid,
            "--output",
            output_path,
            input_path,
        ]

        with subprocess.Popen(args) as _proc:
            # read file contents up to limit
            with open(input_path, "wb") as input_pipe:
                chunk_size = 1024
                n_chunks = int(limit / chunk_size)
                with open(filename, "rb") as input_file:
                    for chunk_id in range(n_chunks):
                        input_pipe.write(input_file.read(chunk_size))

                    final_chunk_size = limit - (n_chunks * chunk_size)
                    if final_chunk_size != 0:
                        input_pipe.write(input_file.read(final_chunk_size))

                    input_pipe.close()

        # read output
        with open(output_path, "rb") as output:
            signature = output.read().decode()

        os.unlink(output_path)
        os.unlink(input_path)
        return signature
