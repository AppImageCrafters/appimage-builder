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
import fnmatch
import logging
import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path
from urllib import request


class AppRunSetupError(RuntimeError):
    pass


class AppRun:
    env = {
        "APPIMAGE_UUID": None,
        "SYSTEM_INTERP": None,
        "XDG_DATA_DIRS": "$APPDIR/usr/local/share:$APPDIR/usr/share:$XDG_CONFIG_DIRS",
        "XDG_CONFIG_DIRS": "$APPDIR/etc/xdg:$XDG_CONFIG_DIRS",
        "LD_PRELOAD": "libapprun_hooks.so",
    }

    # arch mappings from the file command output to the debian format
    archs_mapping = {
        "ARM aarch64": "aarch64",
        "ARM": "gnueabihf",
        "Intel 80386": "i386",
        "x86-64": "x86_64",
    }

    sections = {}

    def __init__(
        self,
        version,
        debug,
        app_dir,
        exec_path,
        exec_args="$@",
        cache_dir="appimage-builder-cache/runtime",
    ):
        self.app_dir = Path(app_dir).absolute()
        self.apprun_version = version
        self.apprun_build_type = "Debug" if debug else "Release"
        self.env["APPIMAGE_UUID"] = str(uuid.uuid4())
        self.env["EXEC_PATH"] = "$APPDIR/%s" % exec_path
        self.env["EXEC_ARGS"] = exec_args
        self.cache_dir = Path(cache_dir).absolute()

    def deploy(self):
        embed_archs = self._get_embed_libc_archs()

        # deploy AppRun
        apprun_path = self._get_apprun_binary(embed_archs[0])
        logging.info("Deploying: %s => %s" % (apprun_path, self.app_dir / "AppRun"))
        shutil.copy(apprun_path, self.app_dir / "AppRun")
        apprun_path.chmod(
            stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH
        )

        for arch in embed_archs:
            hooks_lib = self._get_apprun_hooks_library(arch)
            target_lib_dir = self._find_hooks_lib_target_lib_dir(arch)
            logging.info("Deploying: %s => %s" % (hooks_lib, target_lib_dir))
            shutil.copy(hooks_lib, os.path.join(target_lib_dir, "libapprun_hooks.so"))

        self._generate_env_file()

    def _get_embed_libc_archs(self):
        libc_paths = self._find_libc_paths()
        if not libc_paths:
            raise AppRunSetupError("Unable to locate libc at: %s" % self.app_dir)

        archs = set()
        for path in libc_paths:
            arch = self._get_elf_arch(path)
            if arch:
                archs.add(arch)
        return list(archs)

    def _generate_env_file(self):
        with open(os.path.join(self.app_dir, ".env"), "w") as f:
            for k, v in self.env.items():
                f.write("%s=%s\n" % (k, v))

    def _get_elf_arch(self, file):
        proc_env = os.environ.copy()
        proc_env["LC_ALL"] = "C"
        proc = subprocess.run(
            ["file", "-b", file], stdout=subprocess.PIPE, env=proc_env
        )
        output = proc.stdout.decode("utf-8")

        parts = output.split(",")
        signature = ",".join(parts[1:2])
        signature = signature.replace("shared object", "")
        signature = signature.replace("executable", "")
        return signature.strip(" ")

    def _find_libc_paths(self):
        paths = []
        for base_path, dirs, files in os.walk(self.app_dir):
            for file in files:
                abs_path = os.path.join(base_path, file)
                if fnmatch.fnmatch(abs_path, "*/libc.so*"):
                    paths.append(abs_path)
                if fnmatch.fnmatch(abs_path, "*/libc-*.so*"):
                    paths.append(abs_path)
        return paths

    def _find_hooks_lib_target_lib_dir(self, arch):
        lib_dirs = self.env["APPDIR_LIBRARY_PATH"]
        lib_dirs = lib_dirs.replace("$APPDIR", str(self.app_dir))
        lib_dirs = lib_dirs.replace("$APPDIR", str(self.app_dir))
        lib_dirs = lib_dirs.split(":")
        for lib_dir in lib_dirs:
            for file in os.listdir(lib_dir):
                file_path = os.path.join(lib_dir, file)
                if os.path.isfile(file_path):
                    file_arch = self._get_elf_arch(file_path)
                    if file_arch == arch:
                        return lib_dir

    def _get_apprun_binary(self, arch):
        if arch not in self.archs_mapping:
            raise AppRunSetupError("Non-supported architecture: '%s'" % arch)

        self.cache_dir.mkdir(parents=True, exist_ok=True)

        apprun_asset = "AppRun-%s-%s" % (
            self.apprun_build_type,
            self.archs_mapping[arch],
        )
        apprun_file = self.cache_dir / apprun_asset
        if not apprun_file.exists():
            url = (
                "https://github.com/AppImageCrafters/AppRun/releases/download/%s/%s"
                % (self.apprun_version, apprun_asset)
            )
            logging.info("Downloading: %s" % url)
            request.urlretrieve(url, apprun_file)

        return apprun_file

    def _get_apprun_hooks_library(self, arch):
        if arch not in self.archs_mapping:
            raise AppRunSetupError("Non-supported architecture: '%s'" % arch)

        self.cache_dir.mkdir(parents=True, exist_ok=True)

        asset = "libapprun_hooks-%s-%s.so" % (
            self.apprun_build_type,
            self.archs_mapping[arch],
        )
        file = self.cache_dir / asset
        if not file.exists():
            url = (
                "https://github.com/AppImageCrafters/AppRun/releases/download/%s/%s"
                % (self.apprun_version, asset)
            )
            logging.info("Downloading: %s" % url)
            request.urlretrieve(url, file)

        return file
