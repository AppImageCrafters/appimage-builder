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
    class ItemResolver():
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
            self.right = self.path.split('/')
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
                raise RecipeError('\'%s\' key required in: %s' % (self.key, '/'.join(self.left)))

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

    def get_item(self, path, fallback=None):
        resolver = Recipe.ItemResolver(self.recipe, path, fallback)
        return resolver.resolve()
