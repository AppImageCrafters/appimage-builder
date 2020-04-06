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


import os
import stat
import uuid


class WrapperAppRun:
    env = {
        'APPIMAGE_UUID': None,
        'LIBRARY_PATH': '',
        'INTERPRETER': None,
        'XDG_DATA_DIRS': '${APPDIR}/usr/local/share:${APPDIR}/usr/share:${XDG_DATA_DIRS}',
        'XDG_CONFIG_DIRS': '$APPDIR/etc/xdg:$XDG_CONFIG_DIRS',
        'PATH': '$APPDIR/bin:$APPDIR/sbin:$APPDIR/usr/bin:$PATH',
        'EXEC_ARGS': '$@',
    }
    sections = {
        'HEADER': [
            '#!/bin/bash',
            '# This file was created by AppImageBuilder',
            '',
            'if [ ! -z "$APPIMAGE_DEBUG" ]; then set -ex; fi',
            '',
        ],
        'APPDIR': [
            '# Fallback APPDIR variable setup for uncompressed usage',
            'if [ -z ${APPDIR+x} ]; then',
            '    export APPRUN_ORIGINAL_APPDIR=""',
            '    export APPDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"',
            '    export APPRUN_STARTUP_APPDIR="$APPDIR"',
            'fi'
        ],
        'LINKER': [
            '',
            '# Query executables PT_NEEED to resolve libc.so paths',
            'SYSTEM_COMMAND_NEEDS=$("${INTERPRETER}" --library-path $APPDIR_LIBRARY_PATH:$LD_LIBRARY_PATH --list "$APPDIR/$BIN_PATH")',
        ],
        'LIBC': [
            'GREP="$INTERPRETER $APPDIR/bin/grep"',
            'CUT="$INTERPRETER $APPDIR/usr/bin/cut"',
            'SORT="$INTERPRETER $APPDIR/usr/bin/sort"',
            'TAIL="$INTERPRETER $APPDIR/usr/bin/tail"',
            'DIRNAME="$INTERPRETER $APPDIR/usr/bin/dirname"',

            '###',
            '# Select the greater libc to run the app',
            '###',
            'function extract_libc_path() {',
            '   LD_LIST_OUTPUT="$1"',
            '   echo "$LD_LIST_OUTPUT" | $GREP "libc.so" | $CUT -f 3 -d " "',
            '}',
            'function extract_libc_version() {',
            '   LIBC_PATH="$1"',
            '   $GREP  -Eao \'GLIBC_[0-9]{1,4}\\.[0-9]{1,4}\' $LIBC_PATH | $GREP -Eao \'[0-9]{1,4}\\.[0-9]{1,4}\' | $SORT -V | $TAIL -1',
            '}',

            '',
            'echo "AppRun -- resolving greater libc --"',
            '',
            'export APPRUN_ORIGINAL_LD_LIBRARY_PATH="$LD_LIBRARY_PATH"',
            'export LD_LIBRARY_PATH="$APPDIR_LIBRARY_PATH:$LIBC_LIBRARY_PATH:$APPRUN_ORIGINAL_LD_LIBRARY_PATH"',
            'export APPRUN_STARTUP_LD_LIBRARY_PATH="$LD_LIBRARY_PATH"',
            'SYSTEM_LIBC_PATH=$(extract_libc_path "$SYSTEM_COMMAND_NEEDS")',
            'SYSTEM_LIBC_VERSION=$(extract_libc_version "$SYSTEM_LIBC_PATH")',
            'echo "AppRun -- system libc: $SYSTEM_LIBC_PATH $SYSTEM_LIBC_VERSION"',
            '',
            'GREATER_LIBC=$(echo -e "$SYSTEM_LIBC_VERSION\\n$APPDIR_LIBC_VERSION"  | $SORT -V | $TAIL -1)',
            '',
            'if [ "$SYSTEM_LIBC_VERSION" == "$GREATER_LIBC" ]; then',
            '  echo "AppRun -- Using System libc version: $SYSTEM_LIBC_VERSION"',
            '  LIBC_DIR=$($DIRNAME $SYSTEM_LIBC_PATH)',
            '  export INTERPRETER=$(echo $LIBC_DIR/ld-*.so)',
            '  export APPRUN_STARTUP_SYSTEM_INTERPRETER=$SYSTEM_INTERPRETER',

            '  export LD_LIBRARY_PATH="$APPDIR_LIBRARY_PATH:$APPRUN_ORIGINAL_LD_LIBRARY_PATH"',
            '  export APPRUN_STARTUP_LD_LIBRARY_PATH="$LD_LIBRARY_PATH"',
            'else',
            '  echo "AppRun -- Using AppDir libc version: $APPDIR_LIBC_VERSION"',
            'fi'
        ],
        'EXEC': [
            '# Launch application',
            'exec $INTERPRETER ${APPDIR}/${BIN_PATH} ${EXEC_ARGS}',
            ''
        ]
    }

    def __init__(self, bin_path, exec_args=None):
        assert bin_path

        self.env['BIN_PATH'] = bin_path
        if exec_args:
            self.env['EXEC_ARGS'] = exec_args

        self.env['APPIMAGE_UUID'] = str(uuid.uuid4())

    def save(self, path):
        lines = self._generate()

        with open(path, "w") as f:
            f.write("\n".join(lines))

        self._set_permissions(path)

    def _generate(self):
        file_lines = []
        file_lines.extend(self.sections['HEADER'])
        file_lines.extend(self.sections['APPDIR'])

        if self.env['INTERPRETER']:
            file_lines.append('# Guess libc to use')

            for env in ['APPIMAGE_UUID', 'INTERPRETER', 'BIN_PATH']:
                file_lines.extend(self._generate_env(env, self.env[env]))

            for k in self.env:
                if '_LIBRARY_PATH' in k:
                    file_lines.extend(self._generate_env(k, self.env[k]))

            file_lines.extend(self.sections['LINKER'])

        file_lines.extend(self._generate_env_section())
        file_lines.extend(self.sections['LIBC'])

        for k, v in self.sections.items():
            if k not in ['HEADER', 'APPDIR', 'LINKER', 'LIBC', 'EXEC', 'EXEC_ARGS']:
                # avoid including any special section
                file_lines.extend(['', '# %s' % k])
                file_lines.extend(v)

        file_lines.extend(self._generate_env('LD_PRELOAD', self.env['LD_PRELOAD']))
        file_lines.extend(self.sections['EXEC'])

        return file_lines

    def _generate_env_section(self):
        lines = ['', '# Run Environment Setup']
        for k, v in self.env.items():
            if 'LIBRARY_PATH' not in k and k not in ['APPIMAGE_UUID', 'INTERPRETER', 'INTERPRETER_RELATIVE',
                                                     'LD_PRELOAD'] and v:
                lines.extend(self._generate_env(k, v))

        lines.append('')
        return lines

    def _generate_env(self, k, v):
        lines = [
            'export APPRUN_ORIGINAL_%s="$%s"' % (k, k),
            'export %s="%s"' % (k, v),
            'export APPRUN_STARTUP_%s="$%s"' % (k, k),
        ]

        return lines

    def _set_permissions(self, path):
        os.chmod(path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH)
