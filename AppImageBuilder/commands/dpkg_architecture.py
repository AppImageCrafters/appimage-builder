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


import subprocess
from .command import Command


class DpkgArchitecture(Command):
    def __init__(self):
        super().__init__('dpkg-architecture')

    def get_deb_host_arch(self):
        return self._query('DEB_HOST_ARCH')

    def _query(self, var_name):
        result = subprocess.run(['dpkg-architecture', '-q', var_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return result.stdout.decode('utf-8').strip()
        else:
            return None
