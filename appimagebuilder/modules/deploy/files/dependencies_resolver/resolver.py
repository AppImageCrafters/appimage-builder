#  Copyright  2022 Alexis Lopez Zubieta
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
import pathlib

from .base_resolver import BaseResolver
from .elf_resolver import ElfResolver


class Resolver(BaseResolver):
    """
    Collection of heuristic methods to resolve application dependencies based of file paths.
    """

    def __init__(self):
        self.resolvers = [ElfResolver()]

    def resolve(self, files: [pathlib.Path]) -> [pathlib.Path]:
        results = set()
        for resolver in self.resolvers:
            partial_results = resolver.resolve(files)
            results.update(partial_results)

        return list(results)
