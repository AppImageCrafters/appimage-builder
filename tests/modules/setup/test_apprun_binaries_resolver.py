import pathlib
import unittest

from appimagebuilder.modules.setup.apprun_binaries_resolver import (
    AppRunBinariesResolver,
)


class AppRunBinariesResolverLocationTestCase(unittest.TestCase):
    def test_cache_dir_under_given_dir(self) -> None:
        base: pathlib.Path = pathlib.Path("/tmp/b")
        resolver: AppRunBinariesResolver = AppRunBinariesResolver("v3.0.0", False, base)
        self.assertEqual(resolver.cache_dir, base / "AppRun" / "v3.0.0")


if __name__ == "__main__":
    unittest.main()
