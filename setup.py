#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  Copyright  2020 Alexis Lopez Zubieta
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

import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="appimage_builder",
    version="0.8.5",
    author="Alexis Lopez Zubieta",
    author_email="contact@azubieta.net",
    description="Recipe based AppImage creation meta-tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    scripts=["appimage-modules", "appimage-inspector"],
    entry_points={
        "console_scripts": [
            "appimage-builder = appimagebuilder.__main__:__main__",
            "appimage-tester = appimagebuilder.tester.__main__:__main__",
        ]
    },
    url="https://github.com/AppImageCrafters/appimage-builder",
    project_urls={
        "Bug Tracker": "https://github.com/AppImageCrafters/appimage-builder/issues",
        "Documentation": "https://appimage-builder.readthedocs.io",
        "Source Code": "https://github.com/AppImageCrafters/appimage-builder",
    },
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    license="MIT",
    install_requires=[
        "pyyaml>=5",
        "docker",
        "requests",
        "schema",
        "packaging",
        "questionary",
        "emrichen",
    ],
    python_requires=">=3.6",
    package_data={
        "": [
            "appimagebuilder/generator/templates/apt.yml.in",
            "appimagebuilder/generator/templates/files.yml.in",
            "appimagebuilder/tester/utils/entry_point.sh",
            "appimagebuilder/tester/utils/static_test.sh",
        ]
    },
    include_package_data=True,
)
