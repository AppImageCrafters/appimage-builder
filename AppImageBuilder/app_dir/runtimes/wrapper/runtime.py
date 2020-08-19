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

from AppImageBuilder.app_dir.metadata.loader import AppInfoLoader
from AppImageBuilder.recipe import Recipe
from .app_run import WrapperAppRun
from .helpers.factory import HelperFactory


class WrapperRuntimeError(RuntimeError):
    pass


class WrapperRuntime():
    def __init__(self, recipe: Recipe):
        self._configure(recipe)
        self.app_run_constructor = WrapperAppRun
        self.helper_factory_constructor = HelperFactory

    def _configure(self, recipe):
        self.app_dir = recipe.get_item('AppDir/path')
        self.app_dir = os.path.abspath(self.app_dir)

        app_info_loader = AppInfoLoader()
        self.app_info = app_info_loader.load(recipe)
        self.env = recipe.get_item('AppDir/runtime/env', {})
        self.path_mappings = recipe.get_item('AppDir/runtime/path_mappings', [])

    def generate(self):
        app_run = self.app_run_constructor(self.app_dir, self.app_info.exec, self.app_info.exec_args)
        self._configure_runtime(app_run)
        self._add_user_defined_settings(app_run)

        self._set_path_mappings(app_run)

        app_run.deploy()

    def _configure_runtime(self, app_run):
        app_dir_files = self._get_app_dir_file_list()
        factory = self.helper_factory_constructor(self.app_dir, app_dir_files)
        for id in factory.list():
            h = factory.get(id)
            h.configure(app_run)

    def _get_app_dir_file_list(self):
        app_dir_files = []
        for root, dirs, files in os.walk(self.app_dir):
            for file in files:
                app_dir_files.append(os.path.join(root, file))

        return app_dir_files

    def _add_user_defined_settings(self, app_run: WrapperAppRun) -> None:
        for k, v in self.env.items():
            if k in app_run.env:
                logging.info('Overriding runtime env: %s' % k)

            app_run.env[k] = v

    def _set_path_mappings(self, app_run: WrapperAppRun):
        if self.path_mappings:
            path_mappings_env = ""
            for path_mapping in self.path_mappings:
                path_mappings_env += path_mapping + ';'

            app_run.env['APPRUN_PATH_MAPPINGS'] = path_mappings_env
