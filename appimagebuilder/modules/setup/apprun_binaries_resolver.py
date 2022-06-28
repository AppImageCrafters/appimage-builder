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
import pathlib
import tarfile
from pathlib import Path
from urllib import request

from appimagebuilder.modules.setup import apprun_utils


class AppRunBinariesResolver:
    """Resolves the AppRun binaries from GitHub or the cache"""

    def __init__(
            self,
            version,
            debug,
            build_dir: pathlib.Path,
    ):
        self.apprun_version = version
        self.apprun_build_type = "Debug" if debug else "Release"
        self.cache_dir = build_dir / "AppRun" / version

    def resolve_executable(self, arch):
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        apprun_asset = "AppRun-%s-%s" % (
            self.apprun_build_type,
            arch,
        )
        apprun_file = self.cache_dir / apprun_asset
        if not apprun_file.exists():
            self._download_release_asset(apprun_asset, apprun_file)

        return apprun_file

    def resolve_hooks_library(self, arch):
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        asset = "libapprun_hooks-%s-%s.so" % (self.apprun_build_type, arch)
        file = self.cache_dir / asset
        if not file.exists():
            self._download_release_asset(asset, file)

        return file

    def resolve_check_glibc_binary(self, arch):
        asset = f"check-glibc-{self.apprun_build_type}-{arch}"
        file = (
                self.cache_dir / asset
        )

        if not file.exists():
            self._download_release_asset(asset, file)

        return file

    def _download_release_asset(self, asset, path):
        path.parent.mkdir(parents=True, exist_ok=True)

        url = "https://github.com/AppImageCrafters/AppRun/releases/download/%s/%s" % (
            self.apprun_version,
            asset,
        )
        logging.info("Downloading: %s" % url)
        request.urlretrieve(url, path)
