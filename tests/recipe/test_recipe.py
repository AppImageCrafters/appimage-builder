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
from unittest import TestCase

from appimagebuilder.recipe import Recipe


class TestRecipe(TestCase):
    def test_get_dict_item_with_var(self):
        os.environ["TEST_VAR_1"] = "VALUE1"
        os.environ["TEST_VAR_2"] = "VALUE2"
        recipe = Recipe(
            {
                "K1": {"K2": "{{TEST_VAR_1}} {{TEST_VAR_2}}"},
                "K3": ["{{TEST_VAR_1}}", "{{TEST_VAR_2}}"],
            }
        )
        result = recipe.get_item("K1")
        self.assertEqual({"K2": "VALUE1 VALUE2"}, result)

        result = recipe.get_item("K3")
        self.assertEqual(["VALUE1", "VALUE2"], result)

    def test_get_list_item_with_var(self):
        os.environ["TEST_VAR_1"] = "VALUE1"
        os.environ["TEST_VAR_2"] = "VALUE2"
        recipe = Recipe({"K3": ["{{TEST_VAR_1}}", "{{TEST_VAR_2}}"]})

        result = recipe.get_item("K3")
        self.assertEqual(["VALUE1", "VALUE2"], result)

    def test_get_string_item_with_var(self):
        os.environ["TEST_VAR_1"] = "VALUE1"
        os.environ["TEST_VAR_2"] = "VALUE2"
        recipe = Recipe({"K": "{{TEST_VAR_1}} {{TEST_VAR_2}}"})

        result = recipe.get_item("K")
        self.assertEqual("VALUE1 VALUE2", result)

    def test_get_string_item_with_var_and_spaces(self):
        os.environ["TEST_VAR_1"] = "VALUE1"
        os.environ["TEST_VAR_2"] = "VALUE2"
        recipe = Recipe({"K": "{{ TEST_VAR_1}} {{TEST_VAR_2 }}"})

        result = recipe.get_item("K")
        self.assertEqual("VALUE1 VALUE2", result)

    def test_get_string_item_with_missing_var(self):
        recipe = Recipe({"K": "{{TEST_VAR_MISSING_VAR}}"})

        self.assertRaises(RuntimeError, recipe.get_item, "K")
