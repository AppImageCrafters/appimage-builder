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

import os
import yaml

from AppImageCraft import AppDir2
from AppImageCraft.AppImageBuilder import AppImageBuilder


class ConfigurationError(RuntimeError):
    pass


class Configurator:
    """Read and verify the AppImageCraft recipe and configure the application components"""

    recipe = None
    recipe_path = None

    version = None
    supported_versions = [1]

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
        builder.app_dir_config['path'] = self._check_entry(["AppDir", "path"])
        builder.app_config = self._check_entry(["App"])

        return builder

    def _load_recipe_version(self):
        self.version = self._check_entry(["version"])
        if self.version not in self.supported_versions:
            raise ConfigurationError("Unsupported AppImageCraft recipe version (%s)" % self.version)

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
