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
from pathlib import Path

from appimagebuilder.modules.deploy.pacman.deploy import Deploy
from appimagebuilder.modules.deploy.pacman.venv import Venv
from appimagebuilder.main.commands.deploy_command import DeployCommand


class PacmanDeployCommand(DeployCommand):
    def __init__(
        self,
        app_dir: str,
        cache_dir: str,
        deploy_record,
        packages: [str],
        exclude: [str],
        architecture: str,
        repositories: [str],
        options: dict,
    ):
        super().__init__("pacman deploy", app_dir, cache_dir, deploy_record)

        self._packages = packages
        self._exclude = exclude
        self._architecture = architecture
        self._repositories = repositories
        self._options = options

    def id(self):
        return "pacman-deploy"

    def __call__(self, *args, **kwargs):
        venv = Venv(
            root=Path(self._cache_dir) / "pacman",
            repositories=self._repositories,
            architecture=self._architecture,
            user_options=self._options,
        )

        pacman_deploy = Deploy(venv)
        deployed_packages = pacman_deploy.deploy(
            self._packages, self._app_dir, self._exclude
        )
        self._deploy_record["pacman"] = {
            "packages": deployed_packages,
        }
