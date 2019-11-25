#  Copyright  2019 Alexis Lopez Zubieta
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

import yaml

from AppImageBuilder import drivers
from AppImageBuilder.AppImageBuilder import AppImageBuilder


class ConfigurationError(RuntimeError):
    pass


class Configurator:
    """Read and verify the AppImageBuilder recipe and configure the application components"""

    recipe = None
    recipe_path = None

    version = None
    supported_versions = [1]

    logger = None

    def __init__(self):
        self.logger = logging.getLogger("Configurator")

    def load_file(self, path=None):
        """Load recipe from file"""

        assert os.path.exists(path)
        assert os.path.isfile(path)

        self.recipe_path = path
        with open(path, "r") as f:
            content = f.read()
            return self.load(content)

    def load(self, raw_recipe):
        """Load recipe from string"""
        self.recipe = yaml.load(raw_recipe, Loader=yaml.FullLoader)
        if not self.recipe:
            raise ConfigurationError("Empty recipe")

        self._load_recipe_version()

        builder = AppImageBuilder()
        builder.drivers = {
            drivers.Source.id: drivers.Source(),
            drivers.Linker.id: drivers.Linker(),
            drivers.Dpkg.id: drivers.Dpkg(),
            drivers.Qt.id: drivers.Qt(),
            drivers.Info.id: drivers.Info(),
            drivers.FontConfig.id: drivers.FontConfig(),
            drivers.GStreamer.id: drivers.GStreamer(),
            drivers.LibGL.id: drivers.LibGL(),
        }

        self._load_script(builder)
        self._load_app_dir_config(builder)

        return builder

    def _load_app_dir_config(self, builder):
        app_dir_config = self._check_entry(['AppDir'])
        app_dir_config_keys = ['path', 'exec', 'exec_args', 'test']

        for k, v in app_dir_config.items():

            if k in app_dir_config_keys:
                # store root keys
                builder.app_dir_config[k] = v
                continue

            if k in builder.drivers.keys():
                builder.drivers[k].load_config(v)
                continue

            self.logger.warning("Unknown AppDir entry '%s' will be ignored." % k)

    def _load_recipe_version(self):
        self.version = self._check_entry(["version"])
        if self.version not in self.supported_versions:
            raise ConfigurationError("Unsupported AppImageBuilder recipe version (%s)" % self.version)

    def _check_entry(self, path):
        """Lockup for an entry starting by the recipe root"""
        current = self.recipe
        visited = []
        for item in path:
            if item in current:
                current = current[item]
                visited.append(item)
            else:
                raise ConfigurationError("Missing %s entry in recipe in %s" % (item, " > ".join(visited)))

        return current

    def _check_optional_entry(self, path, fallback):
        """Lockup for an entry starting by the recipe root"""
        current = self.recipe
        visited = []
        for item in path:
            if item in current:
                current = current[item]
                visited.append(item)
            else:
                return fallback

        return current

    def _load_script(self, builder):
        builder.script = self._check_optional_entry(['script'], [])
