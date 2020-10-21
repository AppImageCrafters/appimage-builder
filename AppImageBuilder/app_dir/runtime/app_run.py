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
import os
import shutil
import stat
import subprocess
import uuid
import logging
from urllib import request
from github import Github


class AppRunSetupError(RuntimeError):
    pass


class WrapperAppRun:
    env = {
        "APPIMAGE_UUID": None,
        "SYSTEM_INTERP": None,
        "XDG_DATA_DIRS": "$APPDIR/usr/local/share:$APPDIR/usr/share:${XDG_DATA_DIRS}",
        "XDG_CONFIG_DIRS": "$APPDIR/etc/xdg:$XDG_CONFIG_DIRS",
    }

    sections = {}

    def __init__(self, version, debug, app_dir, exec_path, exec_args="$@"):
        self.app_dir = app_dir
        self.apprun_version = version
        self.apprun_debug = debug
        self.env["APPIMAGE_UUID"] = str(uuid.uuid4())
        self.env["EXEC_PATH"] = "$APPDIR/%s" % exec_path
        self.env["EXEC_ARGS"] = exec_args

    def deploy(self):
        self._download_apprun_binaries()

        embed_archs = self._get_embed_libc_archs()
        apprun_path = self._find_apprun(embed_archs[0])
        shutil.copy(apprun_path, os.path.join(self.app_dir, "AppRun"))
        self._set_execution_permissions(os.path.join(self.app_dir, "AppRun"))

        for arch in embed_archs:
            hooks_lib = self._find_hooks_lib(arch)
            target_lib_dir = self._find_hooks_lib_target_lib_dir(arch)
            if not target_lib_dir:
                raise AppRunSetupError(
                    "Unable to find a lib dir for deploying: %s " % arch
                )
            logging.info("Deploying: %s => %s" % (hooks_lib, target_lib_dir))
            shutil.copy(hooks_lib, os.path.join(target_lib_dir, "libapprun_hooks.so"))

        self.env["LD_PRELOAD"] = "libapprun_hooks.so"
        self._generate_env_file()

    def _get_embed_libc_archs(self):
        libc_paths = self._find_libc_paths()
        if not libc_paths:
            raise AppRunSetupError("Unable to locate libc at: %s" % self.app_dir)

        arch = set()
        for path in libc_paths:
            arch.add(self._get_elf_arch(path))
        return list(arch)

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
        return signature

    def _download_apprun_binaries(self):
        self.apprun_binaries = []
        self.wrapper_binaries = []

        gh = Github()
        gh_repo = gh.get_repo("AppImageCrafters/AppRun")
        gh_release = gh_repo.get_release(self.apprun_version)
        for asset in gh_release.get_assets():
            if not self.apprun_debug and "debug" in asset.name.lower():
                continue

            if self.apprun_debug and "debug" not in asset.name.lower():
                continue

            file_path = os.path.join(
                os.curdir,
                "appimage-builder-cache",
                "%s-%s" % (self.apprun_version, asset.name),
            )

            if not os.path.exists(file_path):
                logging.info(
                    'Downloading "%s" from: %s'
                    % (asset.name, asset.browser_download_url)
                )
                request.urlretrieve(asset.browser_download_url, file_path)

            if "AppRun" in asset.name:
                self.apprun_binaries.append(file_path)

            if "libapprun_hooks" in asset.name:
                self.wrapper_binaries.append(file_path)

    def _find_libc_paths(self):
        paths = []
        for base_path, dirs, files in os.walk(self.app_dir):
            for file in files:
                abs_path = os.path.join(base_path, file)
                if fnmatch.fnmatch(abs_path, "*/libc-*.so"):
                    paths.append(abs_path)
        return paths

    def _find_hooks_lib(self, libc_arch):
        for wrapper in self.wrapper_binaries:
            signature = self._get_elf_arch(wrapper)
            if libc_arch == signature:
                return wrapper

        raise AppRunSetupError("Unable to find a wrapper for: %s" % libc_arch)

    def _find_apprun(self, libc_arch):
        for apprun in self.apprun_binaries:
            arch = self._get_elf_arch(apprun)
            if libc_arch == arch:
                return apprun

        raise AppRunSetupError("Unable to find a AppRun for: %s" % libc_arch)

    def _set_execution_permissions(self, path):
        os.chmod(
            path,
            stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH,
        )

    def _find_hooks_lib_target_lib_dir(self, arch):
        lib_dirs = self.env["APPDIR_LIBRARY_PATH"]
        lib_dirs = lib_dirs.replace("$APPDIR", self.app_dir)
        lib_dirs = lib_dirs.replace("$APPDIR", self.app_dir)
        lib_dirs = lib_dirs.split(":")
        for lib_dir in lib_dirs:
            for file in os.listdir(lib_dir):
                file_path = os.path.join(lib_dir, file)
                if os.path.isfile(file_path):
                    file_arch = self._get_elf_arch(file_path)
                    if file_arch == arch:
                        return lib_dir
