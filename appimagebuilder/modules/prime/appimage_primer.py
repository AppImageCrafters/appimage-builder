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
import itertools
import logging
import os
import pathlib
import shutil
import stat
import subprocess
from urllib import request

import gnupg
import lief
from io import BytesIO

from appimagebuilder.modules.prime.base_primer import BasePrimer


class AppImagePrimer(BasePrimer):
    def __init__(self, context):
        super().__init__(context)
        self.logger = logging.getLogger("AppImagePrimer")
        self.config = self.context.recipe.AppImage
        self.bundle_main_arch = self.config.arch()
        self.carrier_path = (
                self.context.build_dir / "prime" / ("runtime-%s" % self.bundle_main_arch)
        )

        appimage_file_name = self._resolve_appimage_file_name()
        self.appimage_path = pathlib.Path.cwd() / appimage_file_name

    def prime(self):
        if not self.carrier_path.exists():
            self._get_appimage_kit_runtime()

        # create payload
        payload_path = self.context.app_dir.with_suffix(".squashfs")
        self._make_squashfs(self.context.app_dir, payload_path)

        # prepare carrier (a.k.a. "runtime" using a different name to differentiate from the AppRun settings)
        carrier_binary = lief.parse(self.carrier_path.__str__())
        self._add_appimage_update_information(carrier_binary)
        carrier_binary.write(self.appimage_path.__str__())
        self._sign_bundle(carrier_binary, payload_path)
        carrier_binary.write(self.appimage_path.__str__())

        self._add_payload(payload_path)
        self._generate_zsync_file()
        self._make_appimage_executable()

    def _resolve_appimage_file_name(self):
        if not self.context.recipe.AppImage.filename():
            appimage_file_name = "%s-%s-%s.AppImage" % (
                self.context.app_info.name,
                self.context.app_info.version,
                self.bundle_main_arch,
            )
        else:
            appimage_file_name = self.context.recipe.AppImage.filename()

        return appimage_file_name

    def _make_squashfs(self, appdir: pathlib.Path, appdir_squashfs_path):
        mksquashfs_bin = shutil.which("mksquashfs")
        command = [
            mksquashfs_bin,
            str(appdir),
            str(appdir_squashfs_path),
            "-root-owned",
            "-noappend",
            "-reproducible",
        ]
        self.logger.debug(" ".join(command))
        subprocess.run(command, check=True)

    def _get_appimage_kit_runtime(self):
        url = (
                "https://github.com/AppImage/AppImageKit/releases/download/continuous/runtime-%s"
                % self.bundle_main_arch
        )
        logging.info("Downloading: %s" % url)

        os.makedirs(self.carrier_path.parent, exist_ok=True)
        request.urlretrieve(url, self.carrier_path)

    def _add_payload(self, payload_path):
        try:
            with open(self.appimage_path, "ab") as appimage_file:
                with open(payload_path, "rb") as payload_file:
                    shutil.copyfileobj(payload_file, appimage_file)
        except RuntimeError:
            raise
        finally:
            payload_path.unlink(missing_ok=True)

    def _make_appimage_executable(self):
        st = os.stat(self.appimage_path)
        os.chmod(self.appimage_path, st.st_mode | stat.S_IEXEC)

    def _add_appimage_update_information(self, binary):
        update_information = self.config["update-information"]()
        if update_information:
            self.logger.info("Setting update information: \"%s\"" % update_information)
            section = binary.get_section(".upd_info")
            section.content = list(bytes(update_information, "utf-8"))

    def _sign_bundle(self, carrier_elf: lief.Binary, payload_path: pathlib.Path):
        sign_key = self.config["sign-key"]()
        if sign_key:
            gpg = gnupg.GPG()
            # sign both files as if they were together
            with open(self.appimage_path, 'rb') as carrier_file:
                with open(payload_path, 'rb') as payload_file:
                    concatenated_files = ConcatenatedFiles([carrier_file, payload_file])
                    signature = gpg.sign_file(concatenated_files, keyid=sign_key, detach=True)
                    signature_section = carrier_elf.get_section(".sha256_sig")
                    signature_section.content = list(signature.data)

            # resolve secret key id in case a key fingerprint was used
            key = gpg.export_keys(keyids=[sign_key])
            signature_key_section = carrier_elf.get_section(".sig_key")
            signature_key_section.content = list(bytes(key, "utf-8"))

    def _generate_zsync_file(self):
        if self.config['update-information']:
            zsyncmake_bin = shutil.which("zsyncmake")
            command = [zsyncmake_bin, "-u", self.appimage_path.name, self.appimage_path.__str__()]
            self.logger.debug(command)
            subprocess.run(command, check=True)


class ConcatenatedFiles(object):
    def __init__(self, file_objects):
        self.fds = list(reversed(file_objects))

    def read(self, size=None):
        remaining = size
        data = BytesIO()
        while self.fds and (remaining > 0 or remaining is None):
            data_read = self.fds[-1].read(remaining or -1)
            if len(data_read) < remaining or remaining is None:  # exhausted file
                self.fds.pop()
            if not remaining is None:
                remaining -= len(data_read)
            data.write(data_read)
        return data.getvalue()
