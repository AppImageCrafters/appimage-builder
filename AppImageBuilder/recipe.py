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

import yaml


class RecipeError(RuntimeError):
    pass


class Recipe:
    def __init__(self):
        self.path = None
        self.recipe = None

    def load_file(self, path):
        """Load recipe from file"""
        self.path = path

        contents = self._try_get_file_contents()
        self._load_yaml(contents)

    def _try_get_file_contents(self):
        try:
            with open(self.path, "r") as f:
                return f.read()

        except (OSError, IOError) as e:
            raise RecipeError(str(e))

    def _load_yaml(self, content):
        self.recipe = yaml.load(content, Loader=yaml.FullLoader)

        if not self.recipe:
            raise RecipeError("Empty recipe")

    def get_item(self, path):
        parts = path.split('/')
        cur = self.recipe

        for i in range(0, len(parts)):
            key = parts[i]
            if key in cur:
                cur = cur[key]
            else:
                raise RecipeError('Missing key: %s' % '/'.join(parts[0, i]))

        return cur
