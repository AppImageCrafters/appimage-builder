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
import os

from .apt_bundler.bundler import AptBundler
from .apt_bundler.config import Config as AptConfig
from AppImageBuilder.app_dir.proot_runtime.runtime import PRootRuntime
from .wrapper_runtime.runtime import WrapperRuntime
from .yum_bundler.bundler import Bundler as YumBundler
from .yum_bundler.config import Config as YumConfig
from .file_bundler import FileBundler
from .metadata.desktop_entry_generator import DesktopEntryGenerator
from .metadata.icon_bundler import IconBundler
from .metadata.loader import AppInfoLoader
from .runtime.runtime import Runtime


class BuilderError(RuntimeError):
    pass


class Builder:
    def __init__(self, recipe):
        self.recipe = recipe
        self._load_config()

    def _load_config(self):
        self.app_dir_conf = self.recipe.get_item('AppDir')
        self.app_dir_path = os.path.abspath(self.recipe.get_item('AppDir/path'))
        self._load_app_info_config()

        if 'apt' in self.app_dir_conf:
            self.apt_config = AptConfig()
            self.apt_config.apt_prefix = ''
            self.apt_config.load(self.app_dir_conf['apt'])

        self.file_bundler = FileBundler(self.recipe)

    def _load_app_info_config(self):
        loader = AppInfoLoader()
        self.app_info = loader.load(self.recipe)

    def build(self):
        os.makedirs(self.app_dir_path, exist_ok=True)

        if 'apt' in self.app_dir_conf:
            self.apt_config.generate()
            apt = AptBundler(self.apt_config)
            apt.deploy_packages(self.app_dir_path)

        if 'yum' in self.app_dir_conf:
            config = YumConfig(self.recipe)
            config.configure()

            yum = YumBundler(config)
            yum.deploy_packages(self.app_dir_path)

        self.file_bundler.remove_excluded()

        runtime_generator = self.recipe.get_item('AppDir/runtime/generator', "classic")
        if "proot" == runtime_generator:
            runtime = PRootRuntime(self.recipe)
            runtime.generate()
        elif "wrapper" == runtime_generator:
            runtime = WrapperRuntime(self.recipe)
            runtime.generate()
        else:
            runtime = Runtime(self.recipe)
            runtime.generate()

        self._bundle_app_dir_icon()
        self._generate_app_dir_desktop_entry()

    def _bundle_app_dir_icon(self):
        icon_bundler = IconBundler(self.app_dir_path, self.app_info.icon)
        icon_bundler.bundle_icon()

    def _generate_app_dir_desktop_entry(self):
        desktop_entry_editor = DesktopEntryGenerator(self.app_dir_path)
        desktop_entry_editor.generate(self.app_info)
