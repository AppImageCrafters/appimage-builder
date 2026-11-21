import os
import sys
import unittest
from unittest import mock

from appimagebuilder.cli.argparse import ArgumentsParser


class ArgumentsParserTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        env: mock._patch_dict = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("APPIMAGE_BUILDER_BUILD_DIR", None)
        os.environ.pop("APPIMAGE_BUILDER_CACHE_DIR", None)

    def test_build_dir_default(self) -> None:
        with mock.patch.object(sys, "argv", ["appimage-builder"]):
            args = ArgumentsParser().parse()
        self.assertEqual(args.build_dir, os.path.join(os.getcwd(), "appimage-build"))

    def test_build_dir_from_env(self) -> None:
        os.environ["APPIMAGE_BUILDER_BUILD_DIR"] = "/b/env"
        with mock.patch.object(sys, "argv", ["appimage-builder"]):
            args = ArgumentsParser().parse()
        self.assertEqual(args.build_dir, "/b/env")

    def test_build_dir_flag_overrides_env(self) -> None:
        os.environ["APPIMAGE_BUILDER_BUILD_DIR"] = "/b/env"
        with mock.patch.object(
            sys, "argv", ["appimage-builder", "--build-dir", "/b/flag"]
        ):
            args = ArgumentsParser().parse()
        self.assertEqual(args.build_dir, "/b/flag")

    def test_cache_dir_default_is_none(self) -> None:
        with mock.patch.object(sys, "argv", ["appimage-builder"]):
            args = ArgumentsParser().parse()
        self.assertIsNone(args.cache_dir)

    def test_cache_dir_flag(self) -> None:
        with mock.patch.object(
            sys, "argv", ["appimage-builder", "--cache-dir", "/c/flag"]
        ):
            args = ArgumentsParser().parse()
        self.assertEqual(args.cache_dir, "/c/flag")

    def test_cache_dir_from_env(self) -> None:
        os.environ["APPIMAGE_BUILDER_CACHE_DIR"] = "/c/env"
        with mock.patch.object(sys, "argv", ["appimage-builder"]):
            args = ArgumentsParser().parse()
        self.assertEqual(args.cache_dir, "/c/env")

    def test_cache_dir_flag_overrides_env(self) -> None:
        os.environ["APPIMAGE_BUILDER_CACHE_DIR"] = "/c/env"
        with mock.patch.object(
            sys, "argv", ["appimage-builder", "--cache-dir", "/c/flag"]
        ):
            args = ArgumentsParser().parse()
        self.assertEqual(args.cache_dir, "/c/flag")


if __name__ == "__main__":
    unittest.main()
