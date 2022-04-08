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
import fnmatch

from appimagebuilder.modules.deploy.apt import listings
from appimagebuilder.utils.dpkg_query import DpkgQuery


class PackageFilter:
    """
    Filters a given apt packages removing:
    - packages that are required by other packages in the list
    - packages that are known to reduce the bundle portability
    - packages that are useless in a bundle (i.e.: system services)
    """

    def __init__(self):
        self.exclusion_patterns = set().union(
            listings.apt_core, listings.system_services, listings.graphics
        )

    def filter(self, packages):
        # discard duplicates and ease future operations
        packages = set(packages)

        packages = self.discard_simblings(packages)
        packages = self.discard_blacklisted(packages)

        return packages

    def discard_blacklisted(self, packages):
        filtered_packages = set()
        for pkg in packages:
            pkg_name = pkg.split(":")[0]
            if not self._is_package_blacklisted(pkg_name):
                filtered_packages.add(pkg)

        return filtered_packages

    def _is_package_blacklisted(self, pkg_name):
        for pattern in self.exclusion_patterns:
            if fnmatch.fnmatch(pkg_name, pattern):
                return True
        return False

    def discard_simblings(self, packages):
        dpkg_query = DpkgQuery()
        dependency_map = dpkg_query.depends(packages)
        dependencies = set()
        for dependencies_list in dependency_map.values():
            dependencies = dependencies.union(dependencies_list)

        filtered_packages = set()
        for pkg in packages:
            pkg_name = pkg.split(":")[0]
            if pkg_name not in dependencies:
                filtered_packages.add(pkg)

        return filtered_packages
