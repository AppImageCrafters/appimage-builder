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

from .app_info.loader import AppInfoLoader
from .apt.apt import Apt
from .apt.config import Config as AptConfig


class BuilderError(RuntimeError):
    pass


class Builder:
    def __init__(self, recipe):
        self._load_config(recipe)

    def _load_config(self, recipe):
        self._load_app_dir_conf(recipe)
        self._load_app_dir_path()
        self._load_app_info_config()

        if 'apt' in self.app_dir_conf:
            self.apt_config = AptConfig()
            self.apt_config.apt_prefix = ''
            self.apt_config.load(self.app_dir_conf['apt'])

    def _load_app_dir_path(self):
        if 'path' not in self.app_dir_conf:
            raise BuilderError('Missing \'AppDir/path\' entry')
        else:
            self.app_dir_path = os.path.abspath(self.app_dir_conf['path'])

    def _load_app_info_config(self):
        if 'app_info' in self.app_dir_conf:
            loader = AppInfoLoader()
            self.app_info = loader.load(self.app_dir_conf['app_info'])

    def _load_app_dir_conf(self, recipe):
        self.app_dir_conf = recipe.get_item('AppDir')

    def build(self):
        os.makedirs(self.app_dir_path, exist_ok=True)
        self.apt_config.generate()

        apt = Apt(self.apt_config)
        apt.deploy_packages(self.app_dir_path)
