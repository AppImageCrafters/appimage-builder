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

from AppImageBuilder.app_dir.runtimes.proot.runtime import PRootRuntime
from AppImageBuilder.app_dir.runtimes.wrapper.runtime import WrapperRuntime
from AppImageBuilder.app_dir.bundlers.file_bundler import FileBundler
from .metadata.bundle_info import BundleInfo
from .metadata.desktop_entry_generator import DesktopEntryGenerator
from .metadata.icon_bundler import IconBundler
from .metadata.loader import AppInfoLoader
from AppImageBuilder.app_dir.runtimes.classic.runtime import ClassicRuntime
from AppImageBuilder.app_dir.bundlers.factory import BundlerFactory


class BuilderError(RuntimeError):
    pass


class Builder:
    def __init__(self, recipe):
        self.recipe = recipe
        self.bundlers = []
        self.generator = None
        self._load_config()

    def _load_config(self):
        self.app_dir_conf = self.recipe.get_item('AppDir')
        self.cache_dir = os.path.join(os.path.curdir, 'appimage-builder-cache')
        self._load_app_dir_path()
        self._load_app_info_config()

        bundler_factory = BundlerFactory(self.app_dir_path, self.cache_dir)
        bundler_factory.runtime = self.recipe.get_item('AppDir/runtime/generator', "wrapper")

        for bundler_name in bundler_factory.list_bundlers():
            if bundler_name in self.app_dir_conf:
                bundler_settings = self.app_dir_conf[bundler_name]
                bundler = bundler_factory.create(bundler_name, bundler_settings)
                self.bundlers.append(bundler)

        self.file_bundler = FileBundler(self.recipe)

    def _load_app_dir_path(self):
        self.app_dir_path = os.path.abspath(self.recipe.get_item('AppDir/path'))
        os.makedirs(self.app_dir_path, exist_ok=True)

    def _load_app_info_config(self):
        loader = AppInfoLoader()
        self.app_info = loader.load(self.recipe)

    def build(self):
        logging.info("=================")
        logging.info("Generating AppDir")
        logging.info("=================")

        self._bundle_dependencies()
        self._generate_runtime()
        self._write_bundle_information()

    def _bundle_dependencies(self):
        logging.info("")
        logging.info("Bundling dependencies")
        logging.info("---------------------")

        for bundler in self.bundlers:
            bundler.run()

    def _generate_runtime(self):
        runtime_generator = self.recipe.get_item('AppDir/runtime/generator', "wrapper")
        logging.info("")
        logging.info("Generating runtime")
        logging.info("__________________")

        if "proot" == runtime_generator:
            runtime = PRootRuntime(self.recipe)
            runtime.generate()
        if "wrapper" == runtime_generator:
            runtime = WrapperRuntime(self.recipe)
            runtime.generate()
        if "classic" == runtime_generator:
            runtime = ClassicRuntime(self.recipe)
            runtime.generate()

    def _write_bundle_information(self):
        logging.info("")
        logging.info("Generating metadata")
        logging.info("___________________")

        self._bundle_app_dir_icon()
        self._generate_app_dir_desktop_entry()
        self._generate_bundle_info()

    def _bundle_app_dir_icon(self):
        icon_bundler = IconBundler(self.app_dir_path, self.app_info.icon)
        icon_bundler.bundle_icon()

    def _generate_app_dir_desktop_entry(self):
        desktop_entry_editor = DesktopEntryGenerator(self.app_dir_path)
        desktop_entry_editor.generate(self.app_info)

    def _generate_bundle_info(self):
        info = BundleInfo(self.app_dir_path, self.bundlers)
        info.generate()
