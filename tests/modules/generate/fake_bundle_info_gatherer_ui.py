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
from appimagebuilder.modules.generate.bundle_info_gatherer_ui import (
    BundleInfoGathererUi,
)


class FakeBundleInfoGathererUi(BundleInfoGathererUi):
    default_result = "fake input"
    edit_postfix = " edited"

    def ask_text(self, text, default=None):
        if default:
            return default + self.edit_postfix
        else:
            return self.default_result

    def ask_select(self, text, choices, default=None):
        if default:
            return default
        else:
            return choices[-1]
