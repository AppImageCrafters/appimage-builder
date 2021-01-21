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
import logging
import os

from .base_helper import BaseHelper
from ..environment import GlobalEnvironment


class OpenSSL(BaseHelper):
    def configure(self, env: GlobalEnvironment):
        engines_dir = self.app_dir_cache.find_one(
            "*/openssl-*/engines", attrs=["is_dir"]
        )
        if engines_dir:
            env.set("OPENSSL_ENGINES", engines_dir)
