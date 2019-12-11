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
import os

from AppImageBuilder import drivers


class OpenSSL(drivers.Driver):
    id = 'openssl'

    def configure(self, app_dir):
        engines_dir = ''
        for root, dirs, files in os.walk(app_dir.path):
            if 'engines' in dirs and 'openssl-1.0.0' in root:
                engines_dir = os.path.join(root, 'engines')

        if engines_dir:
            app_dir.app_run.env['OPENSSL_ENGINES'] = '${APPDIR}/%s' % engines_dir.replace(app_dir.path, '')
