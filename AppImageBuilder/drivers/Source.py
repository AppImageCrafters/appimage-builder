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
from AppImageBuilder import AppDir2


class Source(drivers.Driver):
    """Special driver to to identify source binaries"""
    id = 'source'

    def list_base_dependencies(self, app_dir):
        dependencies = []
        for file in app_dir.files():
            dependencies.append(SourceDependency(self, file, None))

        return dependencies


class SourceDependency(drivers.Dependency):
    def deploy(self, app_dir):
        pass
