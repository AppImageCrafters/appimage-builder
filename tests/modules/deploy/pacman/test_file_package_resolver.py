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
import pathlib
from unittest import TestCase

from appimagebuilder.modules.generate.package_managers.pacman.file_package_resolver import (
    FilePackageResolver,
)


class TestFilePackageResolver(TestCase):
    def test__parse_pacman_f_output(self):
        sample_pacman_output = """
usr/bin/xmllint is owned by extra/libxml2 2.9.10-9
usr/bin/xmlwf is owned by core/expat 2.3.0-1
usr/bin/xtables-legacy-multi is owned by core/iptables 1:1.8.7-1
"""
        result = FilePackageResolver._parse_pacman_f_output(sample_pacman_output)
        expected = {
            pathlib.Path("usr/bin/xmllint"): "libxml2",
            pathlib.Path("usr/bin/xmlwf"): "expat",
            pathlib.Path("usr/bin/xtables-legacy-multi"): "iptables",
        }
        self.assertEqual(result, expected)
