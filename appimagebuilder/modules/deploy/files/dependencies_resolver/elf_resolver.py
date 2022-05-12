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
import os
import pathlib
import re
import shutil
import subprocess

from .base_resolver import BaseResolver


class ElfResolver(BaseResolver):
    def __init__(self):
        self.needed_libraries_cache = {}

    def resolve(self, files: [pathlib.Path]) -> [pathlib.Path]:
        results = []
        for file in files:
            # skip files that are shown in results as their dependencies are also included
            if file not in results:
                file_results = self.resolve_needed_recursively(file)
                results.extend(file_results)

        return results

    def resolve_needed_recursively(self, file: pathlib) -> [str]:
        # use cache to speed up lookups
        if file in self.needed_libraries_cache:
            needed_libraries = self.needed_libraries_cache[file]
        else:
            needed_libraries = self._resolved_needed_using_ldd(file)
            self.needed_libraries_cache[file] = needed_libraries

        return needed_libraries

    @staticmethod
    def _resolved_needed_using_ldd(file):
        ldd_bin = shutil.which("ldd")

        # set locale to C to avoid output variations due localizations
        _proc_env = os.environ.copy()
        _proc_env["LC_ALL"] = "C"

        _proc = subprocess.run(
            [ldd_bin, str(file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_proc_env,
        )

        # process output
        output = _proc.stdout.decode()
        needed_libraries = []
        for line in output.splitlines():
            # match paths in lines
            path_search = re.search(r"(/.*)\s?\(", line)
            if path_search:
                path = path_search.group(1)
                needed_libraries.append(path.strip())

        return needed_libraries
