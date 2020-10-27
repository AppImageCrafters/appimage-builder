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
import fnmatch
import os
import shutil

from AppImageBuilder.app_dir.file_info_cache import FileInfoCache


class FileDeployHelper:
    """
    Deploy helper that uses the PT_NEEDED entries to resolve dependencies between binaries
    """

    listings = {
        "graphics": [
            "*/libxcb-shm.so*",
            "*/libGL.so*",
            "*/libEGL.so*",
            "*/libX11.so",
            "*/libxcb-shape.so*",
            "*/libxcb-glx.so*",
            "*/libdrm.so*",
            "*/libxcb.so*",
            "*/libxcb-xfixes.so*",
            "*/libxcb-render.so*",
            "*/libX11-xcb.so*",
        ],
        "glibc": [
            "etc/ld.so.conf.d/*",
            "*/libcrypt.so*",
            "*/libnss_compat-*.so",
            "*/ld-linux-x86-64.so*",
            "*/libnss_nis.so*",
            "*/libmemusage.so*",
            "*/libpthread.so*",
            "*/libcrypt.so*",
            "*/libz.so*",
            "*/libpthread-*.so",
            "*/libutil.so*",
            "*/libnsl.so*",
            "*/libnss_nis-*.so",
            "*/libutil-*.so",
            "*/libdl-*.so",
            "*/libmvec-*.so",
            "*/libBrokenLocale.so*",
            "*/libnss_nisplus.so*",
            "*/libgcc_s.so*",
            "*/libnss_compat.so*",
            "*/ld-*.so",
            "*/libz.so*",
            "*/libthread_db-*.so",
            "*/libpcprofile.so",
            "*/librt.so*",
            "*/libnss_nisplus-*.so",
            "*/libnss_hesiod.so*",
            "*/libresolv.so*",
            "*/libBrokenLocale-*.so",
            "*/libc-*.so",
            "*/libnss_hesiod-*.so",
            "*/libSegFault.so",
            "*/libnss_files.so*",
            "*/libc.so*",
            "*/libanl.so*",
            "*/librt-*.so",
            "*/libanl-*.so",
            "*/libresolv-*.so",
            "*/libm.so*",
            "*/libnss_files-*.so",
            "*/libthread_db.so*",
            "*/libdl.so*",
            "*/libnss_dns.so*",
            "*/libnsl-*.so",
            "*/libmvec.so*",
            "*/libnss_dns-*.so",
            "*/libm-*.so",
            "*/ld-linux-x86-64.so*",
            "*/gconv/*",
            "*/audit/*",
            "*/libstdc++.so*",
            "*/libstdcxx/*",
            "*/doc/zlib1g/*",
            "*/doc/libc6/*",
            "*/doc/gcc-10-base/*",
            "*/doc/libgcc-s1/*",
            "*/doc/libcrypt1/*",
            "*/doc/libstdc++6/*",
        ],
    }

    def __init__(self, app_dir: str, includes: [str], include_graphic_libs=False):
        self.app_dir = app_dir
        self.includes = includes
        self.include_graphic_libs = include_graphic_libs
        self.app_dir_cache = FileInfoCache(app_dir)
        self.logger = logging.getLogger("FileDeployHelper")

    def deploy(self):
        self.logger.info("Inspecting AppDir")
        self.app_dir_cache.update()

        for path in self.includes:
            if self.include_graphic_libs or not self._is_a_graphic_library(path):
                self._deploy_file(path)

        self.app_dir_cache.update()
        elf_files = self.app_dir_cache.find("*", attrs=["is_elf"])
        for path in elf_files:
            file_info = self.app_dir_cache.cache[path]
            if "pt_needed" in file_info:
                for lib in file_info["pt_needed"]:
                    self._deploy_lib(lib)

            if "pt_interp" in file_info:
                if not file_info["pt_interp"].startswith("/tmp/appimage-"):
                    self._deploy_file(file_info["pt_interp"])

    def _deploy_file(self, path):
        self.logger.info("deploying %s" % path)
        deploy_path = self._resolve_deploy_path(path)
        os.makedirs(os.path.dirname(deploy_path), exist_ok=True)
        shutil.copy2(path, deploy_path)

    def _is_a_graphic_library(self, path):
        for pattern in self.listings["graphics"]:
            if fnmatch.fnmatch(path, pattern):
                return True

        return False

    def _resolve_deploy_path(self, path: str):
        for pattern in self.listings["glibc"]:
            if fnmatch.fnmatch(path, pattern):
                return self.app_dir.rstrip("/") + "/opt/libc/" + path.lstrip("/")

        return self.app_dir.rstrip("/") + "/" + path.lstrip("/")

    def _deploy_lib(self, lib):
        pass
