import pathlib
import tempfile
import unittest
from unittest import mock

from appimagebuilder.modules.setup.apprun_2.apprun2 import (
    AppRunV2Setup,
    AppRunV2SetupError,
)
from appimagebuilder.utils.finder import Finder


class TestAppRunV2SetupFindLinkerFolder(unittest.TestCase):
    def test_finds_linker_for_each_architecture(self) -> None:
        cases: list[tuple[str, str]] = [
            ("x86_64-linux-gnu", "ld-linux-x86-64.so.2"),
            ("aarch64-linux-gnu", "ld-linux-aarch64.so.1"),
            ("arm-linux-gnueabihf", "ld-linux-armhf.so.3"),
        ]
        for multiarch, linker_name in cases:
            with self.subTest(multiarch=multiarch):
                with tempfile.TemporaryDirectory() as tmp:
                    appdir: pathlib.Path = pathlib.Path(tmp)
                    linker_dir: pathlib.Path = (
                        appdir / "runtime" / "compat" / "usr" / "lib" / multiarch
                    )
                    linker_dir.mkdir(parents=True)
                    (linker_dir / linker_name).write_bytes(b"")

                    setup: AppRunV2Setup = AppRunV2Setup.__new__(AppRunV2Setup)
                    setup.appdir_path = appdir
                    setup.finder = Finder(appdir)

                    with mock.patch.object(
                        Finder, "is_elf_shared_lib", staticmethod(lambda path: True)
                    ):
                        self.assertEqual(linker_dir, setup._find_linker_folder())

    def test_raises_descriptive_error_when_linker_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            appdir: pathlib.Path = pathlib.Path(tmp)
            (appdir / "usr" / "lib" / "aarch64-linux-gnu").mkdir(parents=True)

            setup: AppRunV2Setup = AppRunV2Setup.__new__(AppRunV2Setup)
            setup.appdir_path = appdir
            setup.finder = Finder(appdir)

            with self.assertRaises(AppRunV2SetupError):
                setup._find_linker_folder()


if __name__ == "__main__":
    unittest.main()
