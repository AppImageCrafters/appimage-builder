#   Copyright  2020 Alexis Lopez Zubieta
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#   sell copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
import logging
from unittest import TestCase
from .package_deploy import PackageDeploy


class TestAptPackageDeploy(TestCase):
    def test_deploy(self):
        logging.basicConfig(level=0)
        # execute only if run as the entry point into the program
        pkgDeploy = PackageDeploy(
            "/tmp/apt-deploy-cache",
            ["deb [arch=amd64] http://deb.debian.org/debian/ bullseye main"],
            keys=["https://ftp-master.debian.org/keys/archive-key-10.asc"],
            options={
                # "APT::Get::AllowUnauthenticated": True,
                # "Acquire::AllowInsecureRepositories": True,
            },
        )

        pkgDeploy.deploy(["perl"], "/tmp/AppDir")
