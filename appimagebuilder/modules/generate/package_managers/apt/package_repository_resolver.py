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
import logging
import pathlib


class PackageRepositoryResolver:
    """Resolve which repository provides a given package"""

    def __init__(self):
        self.logger = logging.getLogger(str(self.__class__.__name__))

    def resolve_source_lines(self, packages) -> []:
        source_lines = []

        apt_config_path = pathlib.Path("/etc/apt")
        for sources_list in apt_config_path.glob("**/*.list"):
            with open(sources_list) as list_file:
                for line in list_file.readlines():
                    if line.startswith("deb "):
                        source_line = line.strip()
                        source_lines.append(source_line)

        return source_lines
