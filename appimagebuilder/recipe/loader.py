#  Copyright  2021 Alexis Lopez Zubieta
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
import re

import yaml

from appimagebuilder.recipe.errors import RecipeError
from appimagebuilder.recipe.roamer import Roamer


class Loader:
    """
    Load a yaml configuration file and resolve any environment variables
    The environment variables must have !ENV before them and be in this format
    to be parsed: ${VAR_NAME}.
    E.g.:
    app_info:
        version: !ENV ${APP_VERSION}
        exec: !ENV 'lib/${gnu_arch_triplet}/qt5/bin/qmlscene'
    AppImage:
        arch: !ENV '${TARGET_ARCH}'
        name: !ENV 'myapp-${APP_VERSION}_${TIMESTAMP}-${ARCH}.AppImage'

    reference: https://medium.com/swlh/python-yaml-configuration-with-environment-variables-parsing-77930f4273ac
    """

    def __init__(self):
        self._loader = yaml.SafeLoader

        # the tag will be used to mark where to start searching for the pattern
        # e.g. somekey: !ENV somestring${MYENVVAR}blah blah blah
        self._tag = "!ENV"

        # pattern for global vars: look for ${word}
        pattern = re.compile(".*?\${(\w+)}.*?")

        self._loader.add_implicit_resolver(self._tag, pattern, None)

        def constructor_env_variables(loader, node):
            """
            Extracts the environment variable from the node's value
            :param yaml.Loader loader: the yaml loader
            :param node: the current node in the yaml
            :return: the parsed string that contains the value of the environment
            variable
            """
            value = loader.construct_scalar(node)
            match = pattern.findall(value)  # to find all env variables in line
            if match:
                full_value = value
                for g in match:
                    value = os.environ.get(g, g)
                    if value == g:
                        raise RecipeError(
                            "Unable to resolve environment variable: %s" % g
                        )

                    full_value = full_value.replace(f"${{{g}}}", value)
                return full_value
            return value

        self._loader.add_constructor(self._tag, constructor_env_variables)

    def load(self, path):
        with open(path) as recipe_file:
            return yaml.load(recipe_file, Loader=self._loader)
