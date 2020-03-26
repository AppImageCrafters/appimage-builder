#  Copyright  2020 Alexis Lopez Zubieta
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

import unittest

from .bundler import Bundler


class BundlerTestCase(unittest.TestCase):
    def test_resolve_partition_path(self):
        bundler = Bundler(None)

        bundler.partitions = {'test': ['package']}
        self.assertEqual('/test', bundler._resolve_partition_path('package', '/'))
        self.assertEqual('/', bundler._resolve_partition_path('package_2', '/'))