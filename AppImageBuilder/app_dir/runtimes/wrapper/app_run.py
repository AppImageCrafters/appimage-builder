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
            '    export APPIMAGE_ORIGINAL_APPDIR=""',
            '    export APPDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"',
            '    export APPIMAGE_STARTUP_APPDIR="$APPDIR"',
            'fi'
        ],
        'LINKER': [
            '',
            'cp -f "$INTERPRETER_RELATIVE" "$INTERPRETER"',
            '',
            '# Query executables PT_NEEED to resolve libc.so paths',
            'SYSTEM_COMMAND_NEEDS=$("${INTERPRETER}" --list /bin/bash)',
            'APPDIR_COMMAND_NEEDS=$(LD_LIBRARY_PATH="$APPDIR_LIBRARY_PATH:$LIBC_LIBRARY_PATH" "$INTERPRETER" '
                '--list $APPDIR/bin/ln)',
        ],
        'LIBC': [
            '###',
            '# Select the greater libc to run the app',
            '###',
            'function extract_libc_path() {',
            '   LD_LIST_OUTPUT="$1"',
            '   echo "$LD_LIST_OUTPUT" | grep "libc.so" | cut -f 3 -d " "',
            '}',
            'function extract_libc_version() {',
            '   LIBC_PATH="$1"',
            '   grep  -Eao \'GLIBC_[0-9]{1,4}\\.[0-9]{1,4}\' $LIBC_PATH | grep -Eao \'[0-9]{1,4}\\.[0-9]{1,4}\' | sort -V | tail -1',
            '}',

            '',
            'echo "AppRun -- resolving greater libc --"',
            '',
            'export APPIMAGE_ORIGINAL_LD_LIBRARY_PATH="$LD_LIBRARY_PATH"',
            'export LD_LIBRARY_PATH="$APPDIR_LIBRARY_PATH:$LIBC_LIBRARY_PATH:$APPIMAGE_ORIGINAL_LD_LIBRARY_PATH"',
            'export APPIMAGE_STARTUP_LD_LIBRARY_PATH="$LD_LIBRARY_PATH"',
            'SYSTEM_LIBC_PATH=$(extract_libc_path "$SYSTEM_COMMAND_NEEDS")',
            'SYSTEM_LIBC_VERSION=$(extract_libc_version "$SYSTEM_LIBC_PATH")',
            'echo "AppRun -- system libc: $SYSTEM_LIBC_PATH $SYSTEM_LIBC_VERSION"',
            '',
            'APPDIR_LIBC_PATH=$(extract_libc_path "$APPDIR_COMMAND_NEEDS")',
            'APPDIR_LIBC_VERSION=$(extract_libc_version "$APPDIR_LIBC_PATH")',
            'echo "AppRun -- appdir libc: $APPDIR_LIBC_PATH $APPDIR_LIBC_VERSION"',
            '',
            'GREATER_LIBC=$(echo -e "$SYSTEM_LIBC_VERSION\\n$APPDIR_LIBC_VERSION"  | sort -V | tail -1)',
            '',
            'if [ "$SYSTEM_LIBC_VERSION" == "$GREATER_LIBC" ]; then',
            '  echo "AppRun -- Using System libc version: $SYSTEM_LIBC_VERSION"',
            '  LIBC_DIR=$(dirname $SYSTEM_LIBC_PATH)',
            '  export SYSTEM_INTERPRETER=$(echo $LIBC_DIR/ld-*.so)',
            '  export APPIMAGE_STARTUP_SYSTEM_INTERPRETER=$SYSTEM_INTERPRETER',
            '',
            '  # use system loader',
            '  cp -f "$SYSTEM_INTERPRETER" "$INTERPRETER"',
            '',
            '  export LD_LIBRARY_PATH="$APPDIR_LIBRARY_PATH:$APPIMAGE_ORIGINAL_LD_LIBRARY_PATH"',
            '  export APPIMAGE_STARTUP_LD_LIBRARY_PATH="$LD_LIBRARY_PATH"',
            'else',
            '  echo "AppRun -- Using AppDir libc version: $APPDIR_LIBC_VERSION"',
            'fi'
        ],
        'EXEC': [
            '# Launch application',
            'exec ${APPDIR}/${BIN_PATH} ${EXEC_ARGS}',
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

            for env in ['APPIMAGE_UUID', 'INTERPRETER', 'INTERPRETER_RELATIVE']:
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

        file_lines.extend(self.sections['EXEC'])

        return file_lines

    def _generate_env_section(self):
        lines = ['', '# Run Environment Setup']
        for k, v in self.env.items():
            if 'LIBRARY_PATH' not in k and k not in ['APPIMAGE_UUID', 'INTERPRETER', 'INTERPRETER_RELATIVE'] and v:
                lines.extend(self._generate_env(k, v))

        lines.append('')
        return lines

    def _generate_env(self, k, v):
        lines = [
            'export APPIMAGE_ORIGINAL_%s="$%s"' % (k, k),
            'export %s="%s"' % (k, v),
            'export APPIMAGE_STARTUP_%s="$%s"' % (k, k),
        ]

        return lines

    def _set_permissions(self, path):
        os.chmod(path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH)
