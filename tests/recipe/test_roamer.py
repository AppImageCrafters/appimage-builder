import os
from unittest import TestCase
from unittest.mock import patch

from appimagebuilder.recipe.roamer import Roamer


class TestRoamer(TestCase):
    def test_indexed_recipe_values_resolve_environment_variables(self):
        architecture = "x86_64-synthetic"
        with patch.dict(os.environ, {"APPIMAGE_ARCHITECTURE_FIXTURE": architecture}):
            recipe = Roamer(
                {
                    "AppImage": {
                        "file_name": "bundle-{{APPIMAGE_ARCHITECTURE_FIXTURE}}.AppImage",
                        "update-information": (
                            "synthetic|owner|repo|latest|"
                            "bundle-{{APPIMAGE_ARCHITECTURE_FIXTURE}}.AppImage.zsync"
                        ),
                    }
                }
            )

            self.assertEqual(
                recipe.AppImage.file_name(),
                "bundle-x86_64-synthetic.AppImage",
            )
            self.assertEqual(
                recipe.AppImage["update-information"](),
                "synthetic|owner|repo|latest|bundle-x86_64-synthetic.AppImage.zsync",
            )
