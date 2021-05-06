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


class AppInfo:
    id: str
    name: str
    icon: str
    version: str
    exec: str
    exec_args: str

    def __init__(
        self,
        id: str = None,
        name: str = None,
        icon: str = None,
        version: str = None,
        exec: str = None,
        exec_args: str = None,
    ):
        self.id = id
        self.name = name
        self.icon = icon
        self.version = version
        self.exec = exec
        self.exec_args = exec_args
