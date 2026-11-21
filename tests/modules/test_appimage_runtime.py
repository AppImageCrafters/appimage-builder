import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import roam

from appimagebuilder.context import Context
from appimagebuilder.modules.appimage import AppImageCreator
from appimagebuilder.modules.prime.appimage_primer import AppImagePrimer


class AppImageRuntimeLocationTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        tmp: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root: pathlib.Path = pathlib.Path(tmp.name)
        self.build_dir: pathlib.Path = self.root / "build"

    def test_runtime_and_carrier_under_build_dir(self) -> None:
        context: Context = Context(
            recipe=roam.Roamer({"AppImage": {"arch": "x86_64"}}),
            recipe_path=self.root / "AppImageBuilder.yml",
            app_info=SimpleNamespace(name="app", version="1.0"),
            bundle_info=None,
            app_dir=self.root / "AppDir",
            build_dir=self.build_dir,
        )

        self.assertEqual(
            AppImageCreator(context)._get_runtime_path(),
            str(self.build_dir / "runtime-x86_64"),
        )
        self.assertEqual(
            AppImagePrimer(context).carrier_path,
            self.build_dir / "prime" / "runtime-x86_64",
        )

    def test_runtime_and_carrier_under_cache_dir(self) -> None:
        cache_dir: pathlib.Path = self.root / "cache"
        context: Context = Context(
            recipe=roam.Roamer({"AppImage": {"arch": "x86_64"}}),
            recipe_path=self.root / "AppImageBuilder.yml",
            app_info=SimpleNamespace(name="app", version="1.0"),
            bundle_info=None,
            app_dir=self.root / "AppDir",
            build_dir=self.build_dir,
            cache_dir=cache_dir,
        )

        self.assertEqual(
            AppImageCreator(context)._get_runtime_path(),
            str(cache_dir / "runtime-x86_64"),
        )
        self.assertEqual(
            AppImagePrimer(context).carrier_path,
            cache_dir / "prime" / "runtime-x86_64",
        )

    def test_prime_creates_output_directory(self) -> None:
        output: pathlib.Path = self.root / "missing" / "out" / "app.AppImage"
        context: Context = Context(
            recipe=roam.Roamer(
                {"AppImage": {"arch": "x86_64", "file_name": str(output)}}
            ),
            recipe_path=self.root / "AppImageBuilder.yml",
            app_info=SimpleNamespace(name="app", version="1.0"),
            bundle_info=None,
            app_dir=self.root / "AppDir",
            build_dir=self.build_dir,
        )
        primer: AppImagePrimer = AppImagePrimer(context)
        primer.carrier_path.parent.mkdir(parents=True)
        primer.carrier_path.write_bytes(b"runtime")

        with mock.patch.object(primer, "_make_squashfs"), mock.patch.object(
            primer, "_add_payload"
        ), mock.patch(
            "appimagebuilder.modules.prime.appimage_primer.lief.parse"
        ), mock.patch.object(
            primer, "_add_appimage_update_information"
        ), mock.patch.object(
            primer, "_generate_checksums", return_value=("md5", "sha256")
        ), mock.patch.object(
            primer, "_sign_bundle_sha256_digest"
        ), mock.patch.object(
            primer, "_generate_zsync_file"
        ), mock.patch.object(
            primer, "_make_appimage_executable"
        ):
            primer.prime()

        self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()
