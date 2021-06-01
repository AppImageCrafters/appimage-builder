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
from appimagebuilder.modules.generate.package_managers.apt import (
    PackageRepositoryResolver,
)


class FakePackageRepositoryResolver(PackageRepositoryResolver):
    def resolve_source_lines(self, packages) -> []:
        return [
            "deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse"
        ]
