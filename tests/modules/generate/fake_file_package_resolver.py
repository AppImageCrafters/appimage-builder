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
from appimagebuilder.modules.generate.package_managers.apt import FilePackageResolver


class FakeFilePackageResolver(FilePackageResolver):
    def __init__(self, presets: {}):
        self.presets = presets

    def resolve(self, files) -> {}:
        results = {}

        for file in files:
            if file in self.presets:
                results[file] = self.presets[file]

        return results
