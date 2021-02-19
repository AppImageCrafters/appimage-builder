#   Copyright  2020 Alexis Lopez Zubieta
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#   sell copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
import os
import re

from appimagebuilder.recipe.errors import RecipeError


class Recipe:
    class ItemResolver:
        def __init__(self, dict, path, fallback=None):
            self.root = dict
            self.path = path
            self.fallback = fallback

            self.left = None
            self.right = None
            self.cur = None
            self.key = None

        def resolve(self):
            self.cur = self.root
            self.left = []
            self.right = self.path.split("/")
            try:
                self._resolve_item()
            except KeyError:
                self._fallback_or_raise()

            return self.cur

        def _resolve_item(self):
            while self.right:
                self.key = self.right.pop(0)
                self.cur = self.cur[self.key]

                self.left.append(self.key)

        def _fallback_or_raise(self):
            if self.fallback is not None:
                self.cur = self.fallback
            else:
                raise RecipeError(
                    "'%s' key required in: %s" % (self.key, "/".join(self.left))
                )

    def __init__(self, data):
        self._data = data

    def get_item(self, path, fallback=None):
        resolver = Recipe.ItemResolver(self._data, path, fallback)
        result = resolver.resolve()
        result = self._resolve_variables(result)
        return result

    def _resolve_variables(self, variable):
        if isinstance(variable, str):
            return self._replace_env_variables_in_str(variable)

        if isinstance(variable, list):
            new_list = []
            for v in variable:
                new_list.append(self._resolve_variables(v))
            return new_list

        if isinstance(variable, dict):
            new_dict = {}
            for k, v in variable.items():
                new_dict[k] = self._resolve_variables(v)

            return new_dict

        return variable

    def _replace_env_variables_in_str(self, variable):
        new_val = variable
        for item in re.findall(r"{{\s?\w+\s?}}", variable):
            var_name = item[2:-2]
            var_name = var_name.strip()
            if var_name not in os.environ:
                raise RuntimeError("Missing environment variable: '%s'" % var_name)
            value = os.environ[var_name]
            new_val = new_val.replace(item, value, 1)

        return new_val
