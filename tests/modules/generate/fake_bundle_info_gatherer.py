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

from appimagebuilder.context import BundleInfo
from appimagebuilder.modules.generate.bundle_info_gatherer import BundleInfoGatherer


class FakeBundleInfoGatherer(BundleInfoGatherer):
    def __init__(self, preset_bundle_info):
        self.preset_bundle_info = preset_bundle_info

    def gather_info(self, app_dir: pathlib.Path) -> BundleInfo:
        return self.preset_bundle_info
