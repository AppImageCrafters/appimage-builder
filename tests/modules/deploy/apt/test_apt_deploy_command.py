import pathlib
import unittest
from unittest import mock

from appimagebuilder.commands.apt_deploy import AptDeployCommand


class AptDeployCommandLocationsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.build_dir: pathlib.Path = pathlib.Path("/tmp/build")
        self.context: mock.Mock = mock.Mock()
        self.context.build_dir = self.build_dir
        self.command: AptDeployCommand = AptDeployCommand(
            self.context, ["pkg"], architectures=["x86_64"], sources=[], keys=[]
        )

    def test_apt_venv_under_build_dir(self) -> None:
        self.context.cache_dir = self.build_dir
        with mock.patch("appimagebuilder.commands.apt_deploy.Venv") as venv_cls:
            self.command._setup_apt_venv()

        self.assertEqual(venv_cls.call_args.args[0], str(self.build_dir / "apt"))

    def test_apt_venv_archives_and_lists_under_cache_dir(self) -> None:
        cache_dir: pathlib.Path = pathlib.Path("/tmp/cache")
        self.context.cache_dir = cache_dir
        with mock.patch("appimagebuilder.commands.apt_deploy.Venv") as venv_cls:
            self.command._setup_apt_venv()

        self.assertEqual(venv_cls.call_args.args[0], str(self.build_dir / "apt"))
        self.assertEqual(
            venv_cls.call_args.kwargs["archives_path"], cache_dir / "apt" / "archives"
        )
        self.assertEqual(
            venv_cls.call_args.kwargs["lists_path"], cache_dir / "apt" / "lists"
        )


if __name__ == "__main__":
    unittest.main()
