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

from .app_run import AppRun
from AppImageBuilder.recipe import Recipe, RecipeError
from AppImageBuilder.AppDir.runtime.helpers.factory import HelperFactory


class Runtime():
    def __init__(self, recipe: Recipe):
        self._configure(recipe)

    def _configure(self, recipe):
        self.app_dir = recipe.get_item('AppDir/path')
        self.app_dir = os.path.abspath(self.app_dir)

        self.exec = recipe.get_item('AppDir/app_info/exec')
        self.exec_args = recipe.get_item('AppDir/app_info/exec_args', '$@')

    def generate(self):
        app_run = AppRun(self.exec, self.exec_args)
        self._configure_runtime(app_run)

        app_run_path = self._get_app_run_path()
        app_run.save(app_run_path)

    def _get_app_run_path(self):
        app_run_path = os.path.join(self.app_dir, 'AppRun')
        return app_run_path

    def _configure_runtime(self, app_run):
        app_dir_files = self._get_app_dir_file_list()

        factory = HelperFactory(self.app_dir, app_dir_files)
        for id in factory.list():
            h = factory.get(id)
            h.configure(app_run)

    def _get_app_dir_file_list(self):
        app_dir_files = []
        for root, dirs, files in os.walk(self.app_dir):
            for file in files:
                app_dir_files.append(os.path.join(root, file))

        return app_dir_files
