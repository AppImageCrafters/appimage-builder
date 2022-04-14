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


class TestSectionGenerator:
    def __init__(self):
        self.docker_images = [
            "appimagecrafters/tests-env:fedora-30",
            "appimagecrafters/tests-env:debian-stable",
            "appimagecrafters/tests-env:archlinux-latest",
            "appimagecrafters/tests-env:centos-7",
            "appimagecrafters/tests-env:ubuntu-xenial",
        ]

    def generate(self):
        section = {}
        for image in self.docker_images:
            test_case_title = image.rsplit(":", maxsplit=1)[1]
            section[test_case_title] = {
                "image": image,
                "command": "./AppRun"
            }
        return section
