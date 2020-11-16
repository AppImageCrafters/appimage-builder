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
from pathlib import Path

from appimagebuilder.app_dir.runtime.generator import RuntimeGenerator
from . import deploy
from .app_info.bundle_info import BundleInfo
from .app_info.desktop_entry_generator import DesktopEntryGenerator
from .app_info.icon_bundler import IconBundler
from .app_info.loader import AppInfoLoader
from .file_info_cache import FileInfoCache
from ..script import Script


class BuilderError(RuntimeError):
    pass


class Builder:
    def __init__(self, recipe):
        self.recipe = recipe
        self.generator = None
        self.bundle_info = None
        self.file_info_cache = None
        self._load_config()

    def _load_config(self):
        self.app_dir_conf = self.recipe.get_item("AppDir")
        self.cache_dir = os.path.join(os.path.curdir, "appimage-builder-cache")
        self._load_app_dir_path()
        self._load_app_info_config()
        self.bundle_info = BundleInfo(self.app_dir_path)

    def _load_app_dir_path(self):
        self.app_dir_path = Path(self.recipe.get_item("AppDir/path")).absolute()
        os.makedirs(self.app_dir_path, exist_ok=True)

    def _load_app_info_config(self):
        loader = AppInfoLoader()
        self.app_info = loader.load(self.recipe)

    def build(self):
        logging.info("=================")
        logging.info("Generating AppDir")
        logging.info("=================")

        self.file_info_cache = FileInfoCache(self.recipe.get_item("AppDir/path"))

        scripts_runner = Script()

        scripts_runner.execute(self.recipe.get_item("AppDir/before_bundle", ""))
        self._bundle_dependencies()

        scripts_runner.execute(self.recipe.get_item("AppDir/after_bundle", ""))

        scripts_runner.execute(self.recipe.get_item("AppDir/before_runtime", ""))
        self._generate_runtime()
        scripts_runner.execute(self.recipe.get_item("AppDir/after_runtime", ""))

        self._write_bundle_information()

    def _bundle_dependencies(self):
        logging.info("")
        logging.info("Bundling dependencies")
        logging.info("---------------------")

        if self.recipe.get_item("AppDir/apt", False):
            apt_venv = self._setup_apt_venv()

            apt_deploy = deploy.AptDeploy(apt_venv)
            packages = self.recipe.get_item("AppDir/apt/include")
            packages_excluded = self.recipe.get_item("AppDir/apt/exclude", [])
            deployed_packages = apt_deploy.deploy(
                packages, self.app_dir_path, packages_excluded
            )
            self.bundle_info.data["apt"] = {
                "sources": apt_venv.sources,
                "packages": deployed_packages,
            }

        files_include = self.recipe.get_item("AppDir/files/include", [])
        if files_include:
            file_helper = deploy.FileDeploy(self.app_dir_path)
            file_helper.deploy(files_include)

        self._make_symlinks_relative()
        self.file_info_cache.update()

    def _make_symlinks_relative(self):
        self.file_info_cache.update()
        for link in self.file_info_cache.find("*", attrs=["is_link"]):
            relative_root = (
                self.app_dir_path
                if "opt/libc" not in link
                else self.app_dir_path / "opt" / "libc"
            )
            deploy.make_symlink_relative(link, relative_root)

    def _setup_apt_venv(self):
        sources_list = []
        keys_list = []
        for item in self.recipe.get_item("AppDir/apt/sources"):
            if "sourceline" in item:
                sources_list.append(item["sourceline"])
            if "key_url" in item:
                keys_list.append(item["key_url"])
        apt_arch = self.recipe.get_item("AppDir/apt/arch")
        allow_unauthenticated = self.recipe.get_item(
            "AppDir/apt/allow_unauthenticated", False
        )
        apt_options = {
            "APT::Get::AllowUnauthenticated": allow_unauthenticated,
            "Acquire::AllowInsecureRepositories": allow_unauthenticated,
        }
        apt_venv = deploy.AptVenv(
            Path(self.cache_dir) / "apt",
            sources_list,
            keys_list,
            [apt_arch],
            apt_options,
        )
        return apt_venv

    def _generate_runtime(self):
        logging.info("")
        logging.info("Generating runtime")
        logging.info("__________________")

        runtime = RuntimeGenerator(self.recipe, self.file_info_cache)
        runtime.generate()

    def _write_bundle_information(self):
        logging.info("")
        logging.info("Generating metadata")
        logging.info("___________________")

        self._bundle_app_dir_icon()
        self._generate_app_dir_desktop_entry()
        self.bundle_info.generate()

    def _bundle_app_dir_icon(self):
        icon_bundler = IconBundler(self.app_dir_path, self.app_info.icon)
        icon_bundler.bundle_icon()

    def _generate_app_dir_desktop_entry(self):
        desktop_entry_editor = DesktopEntryGenerator(self.app_dir_path)
        desktop_entry_editor.generate(self.app_info)
