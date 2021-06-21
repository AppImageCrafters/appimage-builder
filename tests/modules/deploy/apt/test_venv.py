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

import shutil
from unittest import TestCase, skipIf

from appimagebuilder.modules.deploy.apt.venv import Venv


@skipIf(not shutil.which("apt-get"), reason="requires apt-get")
class TestVenv(TestCase):
    venv_path = None

    @classmethod
    def setUpClass(cls):
        cls.venv_path = "/tmp/apt-venv"
        cls.apt_venv = Venv(
            cls.venv_path,
            ["deb http://deb.debian.org/debian/ bullseye main"],
            ["https://ftp-master.debian.org/keys/archive-key-10.asc"],
            ["amd64"],
        )
        cls.apt_venv.update()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.venv_path)

    def test_search_names(self):
        self.assertEqual(self.apt_venv.search_names(["perl"]), ["perl"])
        self.assertGreater(self.apt_venv.search_names(["perl*"]), ["perl"])

    def test_search_packages(self):
        self.assertTrue(self.apt_venv.search_packages(["dpkg", "debconf"]))

    def test_set_installed_packages(self):
        packages = self.apt_venv.search_packages(["dpkg", "debconf"])
        # dpkg and debconf need to be set as installed or the configuration step of apt-get install will fail
        self.apt_venv.set_installed_packages(packages)
        with open(self.apt_venv._dpkg_status_path, "r") as f:
            file_contents = f.read()

            self.assertIn(
                "Package: dpkg\n" "Status: install ok installed\n", file_contents
            )

            self.assertIn(
                "Package: debconf\n" "Status: install ok installed\n", file_contents
            )

    def test_resolve_packages(self):
        packages = self.apt_venv.search_packages(["dpkg", "debconf"])
        # dpkg and debconf need to be set as installed or the configuration step of apt-get install will fail
        self.apt_venv.set_installed_packages(packages)

        packages = self.apt_venv.resolve_packages(["libc6"])
        self.assertTrue(packages)

    def test_resolve_archive_paths(self):
        packages = self.apt_venv.search_packages(["tar"])
        paths = self.apt_venv.resolve_archive_paths(packages)
        self.assertTrue(paths)
