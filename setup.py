#  Copyright  2019 Alexis Lopez Zubieta
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

with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name="apppmage_craft",
    version="0.0.2",
    author="Alexis Lopez Zubieta",
    author_email="contact@azubieta.net",
    description="Recipe based AppImage creation meta-tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    scripts=['appimagecraft'],
    url="https://github.com/AppImageCrafters/AppImageCraft",
    project_urls={
        "Bug Tracker": "https://github.com/AppImageCrafters/AppImageCraft/issues",
        "Documentation": "https://github.com/AppImageCrafters/AppImageCraft/wiki",
        "Source Code": "https://github.com/AppImageCrafters/AppImageCraft",
    },
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License"
    ],
    python_requires='>=3.6',
)
