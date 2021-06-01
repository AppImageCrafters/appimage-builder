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
import questionary

from appimagebuilder.modules.generate.bundle_info_gatherer_ui import (
    BundleInfoGathererUi,
)


class BundleInfoGathererCLI(BundleInfoGathererUi):
    def ask_text(self, text, default=None):
        # workaround "TypeError: object of type 'NoneType' has no len()" when default is None
        if default:
            question = questionary.text(
                message=text, default=default, validate=_not_empty_str
            )
        else:
            question = questionary.text(message=text, validate=_not_empty_str)

        return question.ask()

    def ask_select(self, text, choices, default=None):
        # workaround "TypeError: object of type 'NoneType' has no len()" when default is None
        choices = [str(choice) for choice in choices]
        if default:
            question = questionary.select(
                message=text, choices=choices, default=default
            )
        else:
            question = questionary.select(message=text, choices=choices)

        return question.ask()


def _not_empty_str(val):
    return not not val
