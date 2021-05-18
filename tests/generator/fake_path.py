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
import os.path


class FakePath:
    """Mocks pathlib.Path"""

    def __init__(self, path: str, children: [str] = None):
        self.path = path
        self.children = children

    def glob(self, pattern):
        results = []
        for file in self.children:
            if fnmatch.fnmatch(file, pattern):
                results.append(FakePath(file, []))

        return results

    def relative_to(self, fake_path):
        return os.path.relpath(self.path, fake_path.path)

    def __str__(self):
        return self.path

    def __eq__(self, o: object) -> bool:
        return self.__class__ == o.__class__ and self.path == o.path
