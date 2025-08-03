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
from os import environ

class TestSectionGenerator:
    def __init__(self):
        remote_repo = environ["APPIMAGE_BUILDER_REMOTE_REPO_OWNER"]
        self.docker_images = [
            f"{remote_repo}/tests-env:fedora-42",
            f"{remote_repo}/tests-env:debian-bookworm",
            f"{remote_repo}/tests-env:archlinux-latest",
            f"{remote_repo}/tests-env:centos-10",
            f"{remote_repo}/tests-env:ubuntu-noble",
        ]

    def generate(self):
        section = {}
        for image in self.docker_images:
            test_case_title = image.rsplit(":", maxsplit=1)[1]
            section[test_case_title] = {"image": image, "command": "./AppRun"}
        return section
