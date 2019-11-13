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
import os
import shutil

from AppImageCraft import drivers
from AppImageCraft import tools


class LinkerDependency(drivers.Dependency):
    soname = None

    def __init__(self, driver=None, source=None, target=None, soname = None):
        super().__init__(driver, source, target)

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, LinkerDependency):
            # don't attempt to compare against unrelated types
            return False

        return super().__eq__(o) and self.soname == o.soname

    def __str__(self):
        return super().__str__()


class Linker(drivers.Driver):
    id = 'linker'
    linker = None

    def __init__(self):
        self.linker = tools.Linker()

    def lockup_dependencies(self, file):
        dependencies = []
        if not self.linker.linkable(file):
            return None

        linker_map = self.linker.list_link_dependencies(file)
        if linker_map:
            for k, v in linker_map.items():
                if v:
                    dependencies.append(LinkerDependency(self, v, None, k))

        return dependencies
