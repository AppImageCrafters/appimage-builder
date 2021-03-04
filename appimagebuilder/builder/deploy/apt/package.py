#   Copyright  2020 Alexis Lopez Zubieta
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#   sell copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
import urllib

from packaging import version


class Package:
    def __init__(self, name, version, arch):
        # remove arch from the name
        colon_idx = name.find(":")
        if colon_idx != -1:
            self.name = name[:colon_idx]
            self.arch = name[colon_idx + 1 :]
        else:
            self.name = name

        self.version = version
        self.arch = arch

    def get_expected_file_name(self):
        file_name = "%s_%s_%s.deb" % (self.name, self.version, self.arch)

        # apt encodes invalid chars to comply the deb file naming convention
        file_name = urllib.parse.quote(file_name, safe="+*~").lower()
        return file_name

    def get_apt_install_string(self):
        return "%s:%s=%s" % (self.name, self.arch, self.version)

    def __eq__(self, other: object) -> bool:
        """Overrides the default implementation"""
        if isinstance(other, Package):
            return (
                self.name == other.name
                and self.version == other.version
                and self.arch == other.arch
            )
        return False

    def __str__(self):
        """apt input format"""
        output = self.name
        if self.arch:
            output = "%s:%s" % (output, self.arch)
        if self.version:
            output = "%s=%s" % (output, self.version)
        return output

    def __gt__(self, other):
        if isinstance(other, Package):
            return version.parse(self.version) > version.parse(other.version)

    def __hash__(self):
        return self.__str__().__hash__()
