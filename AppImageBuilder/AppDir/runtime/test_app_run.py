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
from .app_run import AppRun


class AppRunTestCase(unittest.TestCase):
    base_script = [
        '#!/bin/bash',
        '# This file was created by AppImageBuilder',
        '',
        '# Fallback APPDIR variable setup for uncompressed usage',
        'if [ -z ${APPDIR+x} ]; then',
        '    APPDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd '
        ')"',
        'fi',
        '',
        '# Run Environment Setup',
        'export XDG_DATA_DIRS="${APPDIR}/usr/local/share:${APPDIR}/usr/share:${XDG_DATA_DIRS}"',
        'export XDG_CONFIG_DIRS="$APPDIR/etc/xdg:$XDG_CONFIG_DIRS"',
        'export EXEC_ARGS="$@"',
        'export BIN_PATH="usr/bin/exec"',
        '',
        '# Launch application using only the bundled libraries',
        'exec "${LINKER_PATH}" \\',
        '   --inhibit-cache --library-path "${LD_LIBRARY_DIRS}" \\',
        '  ${APPDIR}/${BIN_PATH} ${EXEC_ARGS}',
        '']

    def test_minimal_script_generation(self):
        app_run = AppRun('usr/bin/exec')

        lines = app_run._generate()
        self.assertEqual(self.base_script, lines)


if __name__ == '__main__':
    unittest.main()
