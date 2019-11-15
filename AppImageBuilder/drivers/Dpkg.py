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

from AppImageBuilder import drivers
from AppImageBuilder import tools


class DpkgDependency(drivers.Dependency):
    package_name = None

    def __init__(self, driver=None, source=None, target=None, package_name=None):
        super().__init__(driver, source, target)
        self.package_name = package_name

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, DpkgDependency):
            # don't attempt to compare against unrelated types
            return False

        return super().__eq__(o) and self.package_name == o.package_name

    def __str__(self):
        return super().__str__()


class Dpkg(drivers.Driver):
    id = 'dpkg'
    dpkg = None
    cache = {}

    def __init__(self):
        self.dpkg = tools.Dpkg()

    def list_base_dependencies(self, app_dir):
        dependencies = []

        if 'include' in self.config:
            for package in self.config['include']:
                package_files = self.dpkg.list_package_files(package)
                for package_file in package_files:
                    self.cache[package_file] = package

                    dependencies.append(DpkgDependency(self, package_file, None, package))

        return dependencies

    def lockup_file_dependencies(self, file, app_dir):
        if file in self.cache:
            # the files deployed by a single package will always return the same dependencies
            return []
        if file.startswith(app_dir.path):
            # dpkg lockup only work with system files
            return []

        packages = self.dpkg.find_owner_packages(file)

        dependencies = []

        for package in packages:
            package_files = self.dpkg.list_package_files(package)
            for package_file in package_files:
                dependencies.append(DpkgDependency(self, package_file, None, package))

                self.cache[package_file] = package

        return dependencies
