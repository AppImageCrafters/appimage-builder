#  Copyright  2019 Alexis Lopez Zubieta
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

class Hook:
    app_dir = None

    def __init__(self, app_dir):
        self.app_dir = app_dir

    def active(self):
        return False

    def before_install(self):
        pass

    def after_install(self):
        pass

    def app_run_commands(self):
        pass