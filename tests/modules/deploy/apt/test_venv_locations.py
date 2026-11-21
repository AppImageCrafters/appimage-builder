import pathlib
import tempfile
import unittest
from unittest import mock

from appimagebuilder.modules.deploy.apt import Venv


class VenvLocationsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        tmp: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root: pathlib.Path = pathlib.Path(tmp.name)
        self.base: pathlib.Path = self.root / "build" / "apt"
        patcher: mock._patch = mock.patch(
            "appimagebuilder.modules.deploy.apt.venv.shell.require_executables",
            return_value={},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_defaults_under_base_path(self) -> None:
        venv: Venv = Venv(str(self.base), ["deb http://x y z"], [], ["x86_64"], {})
        conf: str = (self.base / "apt.conf").read_text()
        pkg: mock.Mock = mock.Mock()
        pkg.get_expected_file_name.return_value = "a.deb"

        self.assertEqual(venv._apt_archives_path, self.base / "archives")
        self.assertIn(f'Dir "{self.base}";', conf)
        self.assertIn(f'Dir::State "{self.base}";', conf)
        self.assertIn(f'Dir::Cache "{self.base}";', conf)
        self.assertNotIn("Dir::Cache::archives", conf)
        self.assertNotIn("Dir::State::lists", conf)
        self.assertEqual(
            venv.resolve_archive_paths([pkg]), [self.base / "archives" / "a.deb"]
        )

    def test_archives_and_lists_relocated(self) -> None:
        archives: pathlib.Path = self.root / "cache" / "apt" / "archives"
        lists: pathlib.Path = self.root / "cache" / "apt" / "lists"
        venv: Venv = Venv(
            str(self.base),
            ["deb http://x y z"],
            [],
            ["x86_64"],
            {},
            archives_path=archives,
            lists_path=lists,
        )
        conf: str = (self.base / "apt.conf").read_text()
        pkg: mock.Mock = mock.Mock()
        pkg.get_expected_file_name.return_value = "a.deb"

        self.assertEqual(venv._apt_archives_path, archives)
        self.assertIn(f'Dir::Cache::archives "{archives}";', conf)
        self.assertIn(f'Dir::State::lists "{lists}";', conf)
        self.assertTrue(archives.is_dir())
        self.assertTrue((lists / "partial").is_dir())
        self.assertEqual(venv.resolve_archive_paths([pkg]), [archives / "a.deb"])

    def test_user_options_override_archives(self) -> None:
        Venv(
            str(self.base),
            [],
            [],
            ["x86_64"],
            {"Dir::Cache::archives": "/override"},
            archives_path=self.root / "cache" / "archives",
        )
        conf: str = (self.base / "apt.conf").read_text()

        self.assertEqual(conf.count("Dir::Cache::archives"), 1)
        self.assertIn('Dir::Cache::archives "/override";', conf)


if __name__ == "__main__":
    unittest.main()
