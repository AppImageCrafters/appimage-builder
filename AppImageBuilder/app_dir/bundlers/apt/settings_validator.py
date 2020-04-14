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

from schema import Schema, And, Use, Optional


class AptSettingsValidator:

    def __init__(self, settigns):
        self.settings = settigns

        self.schema = Schema({
            Optional('arch'): And(str, len),
            'sources': [{'sourceline': And(str, len), Optional('key_url'): And(str, len)}],
            'include': [And(str, len)],
            Optional('exclude'): [And(str, len)]
        })

    def validate(self):
        self.schema.validate(self.settings)
