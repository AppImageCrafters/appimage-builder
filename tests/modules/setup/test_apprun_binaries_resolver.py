import pathlib
import tempfile
import unittest
from unittest import mock

from appimagebuilder.modules.setup.apprun_binaries_resolver import (
    AppRunBinariesResolver,
)


class AppRunBinariesResolverLocationTestCase(unittest.TestCase):
    def test_cache_dir_under_given_dir(self) -> None:
        base: pathlib.Path = pathlib.Path("/tmp/b")
        resolver: AppRunBinariesResolver = AppRunBinariesResolver("v3.0.0", False, base)
        self.assertEqual(resolver.cache_dir, base / "AppRun" / "v3.0.0")


class AppRunBinariesResolverDownloadTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = pathlib.Path(self._tmp.name)
        self.resolver = AppRunBinariesResolver("v3.0.0", False, self.base)

    def test_downloaded_asset_is_cached(self) -> None:
        def fake_retrieve(url, path):
            pathlib.Path(path).write_bytes(b"data")

        with mock.patch(
            "appimagebuilder.modules.setup.apprun_binaries_resolver.request.urlretrieve",
            side_effect=fake_retrieve,
        ) as retrieve:
            first = self.resolver.resolve_hooks_library("x86_64")
            second = self.resolver.resolve_hooks_library("x86_64")

        self.assertEqual(first, second)
        self.assertEqual(first.read_bytes(), b"data")
        self.assertEqual(retrieve.call_count, 1)

    def test_failed_download_leaves_nothing_in_cache(self) -> None:
        def fake_retrieve(url, path):
            pathlib.Path(path).write_bytes(b"partial")
            raise ConnectionError("dropped")

        with mock.patch(
            "appimagebuilder.modules.setup.apprun_binaries_resolver.request.urlretrieve",
            side_effect=fake_retrieve,
        ):
            with self.assertRaises(ConnectionError):
                self.resolver.resolve_hooks_library("x86_64")

        self.assertEqual(list(self.resolver.cache_dir.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
