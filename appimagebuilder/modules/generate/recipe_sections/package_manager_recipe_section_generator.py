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

from appimagebuilder.context import BundleInfo


class PackageManagerSectionGenerator:
    """Generates a recipe section for a package manager"""

    def id(self) -> str:
        """Identifies the generator"""
        pass

    def generate(self, dependencies: [str], bundle_info: BundleInfo) -> ({}, [str]):
        """
        Generate a recipe section to deploy <dependencies> using the system package manager into the bundle
        Returns: map like recipe section and a list of non-resolved dependencies
        """
        pass
