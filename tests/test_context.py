import pathlib
import unittest

from appimagebuilder.context import Context


class ContextCacheDirTestCase(unittest.TestCase):
    def test_cache_dir_defaults_to_build_dir(self) -> None:
        context: Context = Context(
            recipe=None,
            recipe_path=pathlib.Path("/tmp/r.yml"),
            app_info=None,
            bundle_info=None,
            app_dir=pathlib.Path("/tmp/AppDir"),
            build_dir=pathlib.Path("/tmp/build"),
        )
        self.assertEqual(context.cache_dir, pathlib.Path("/tmp/build"))

    def test_cache_dir_explicit(self) -> None:
        context: Context = Context(
            recipe=None,
            recipe_path=pathlib.Path("/tmp/r.yml"),
            app_info=None,
            bundle_info=None,
            app_dir=pathlib.Path("/tmp/AppDir"),
            build_dir=pathlib.Path("/tmp/build"),
            cache_dir=pathlib.Path("/tmp/cache"),
        )
        self.assertEqual(context.build_dir, pathlib.Path("/tmp/build"))
        self.assertEqual(context.cache_dir, pathlib.Path("/tmp/cache"))


if __name__ == "__main__":
    unittest.main()
