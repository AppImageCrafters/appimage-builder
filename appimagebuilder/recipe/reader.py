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
import re

import yaml

from appimagebuilder.recipe.errors import RecipeError


def read_recipe(path=None, data=None, tag="!ENV"):
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
    :param str path: the path to the yaml file
    :param str data: the yaml data itself as a stream
    :param str tag: the tag to look for
    :return: the dict configuration
    :rtype: dict[str, T]

    reference: https://medium.com/swlh/python-yaml-configuration-with-environment-variables-parsing-77930f4273ac
    """
    # pattern for global vars: look for ${word}
    pattern = re.compile(".*?\${(\w+)}.*?")
    loader = yaml.SafeLoader

    # the tag will be used to mark where to start searching for the pattern
    # e.g. somekey: !ENV somestring${MYENVVAR}blah blah blah
    loader.add_implicit_resolver(tag, pattern, None)

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
                    raise RecipeError("Unable to resolve environment variable: %s" % g)

                full_value = full_value.replace(f"${{{g}}}", value)
            return full_value
        return value

    loader.add_constructor(tag, constructor_env_variables)

    if path:
        with open(path) as conf_data:
            return yaml.load(conf_data, Loader=loader)
    elif data:
        return yaml.load(data, Loader=loader)
    else:
        raise ValueError("Either a path or data should be defined as input")
