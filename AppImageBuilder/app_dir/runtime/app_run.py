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


class AppRun:
    env = {
        'APPIMAGE_UUID': None,
        'LD_LIBRARY_PATH': None,
        'LINKER_PATH': None,
        'XDG_DATA_DIRS': '${APPDIR}/usr/local/share:${APPDIR}/usr/share:${XDG_DATA_DIRS}',
        'XDG_CONFIG_DIRS': '$APPDIR/etc/xdg:$XDG_CONFIG_DIRS',
        'PATH': '$APPDIR/bin:$APPDIR/sbin:$APPDIR/usr/bin:$PATH',
        'EXEC_ARGS': '$@',
    }
    sections = {
        'HEADER': [
            '#!/bin/bash',
            '# This file was created by AppImageBuilder',
            ''
        ],
        'APPDIR': [
            '# Fallback APPDIR variable setup for uncompressed usage',
            'if [ -z ${APPDIR+x} ]; then',
            '    APPDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"',
            'fi'
        ],
        'LINKER': [
            '# Work around for not supported $ORIGIN in the elf PT_INTERP segment',
            'ln -s ${LINKER_PATH} /tmp/appimage_$APPIMAGE_UUID.ld.so --force',
            ''
        ],
        'LIBC': [
            '###',
            '# Select the greater libc to run the app',
            '###',
            '',
            '# Configure appdir loader initially',
            'ln -s ${LINKER_PATH} /tmp/appimage_$APPIMAGE_UUID.ld.so --force',
            'echo "AppRun -- resolving greater libc --"',
            '',
            'SYSTEM_LIBC_PATH=$("${LINKER_PATH}" --list /bin/bash | grep "libc.so" | cut -f 3 -d " ")',
            'SYSTEM_LIBC_VERSION=$(readlink -f "${SYSTEM_LIBC_PATH}" | rev | cut -d / -f 1 | cut -d "-" -f 1 | cut -d '
            '"." -f 2- | rev)',
            'echo "AppRun -- system libc: $SYSTEM_LIBC_PATH $SYSTEM_LIBC_VERSION"',
            '',
            'APPDIR_LIBC_PATH=$("${LINKER_PATH}" --list $APPDIR/$BIN_PATH | grep "libc.so" | cut -f 3 -d " ")',
            'APPDIR_LIBC_VERSION=$(readlink -f "${APPDIR_LIBC_PATH}" | rev | cut -d / -f 1 | cut -d "-" -f 1 | cut -d '
            '"." -f 2- | rev)',
            'echo "AppRun -- appdir libc: $APPDIR_LIBC_PATH $APPDIR_LIBC_VERSION"',
            '',
            'GREATER_LIBC=$(printf "$SYSTEM_LIBC_VERSION\n$APPDIR_LIBC_VERSION"  | sort -V | tail -1)',
            '',
            'if [ "$SYSTEM_LIBC_VERSION" == "$GREATER_LIBC" ]; then',
            '  echo "AppRun -- Using System libc version: $SYSTEM_LIBC_VERSION"',
            '  LIBC_DIR=$(dirname $SYSTEM_LIBC_PATH)',
            '  export LINKER_PATH=$LIBC_DIR/ld-*.so',
            '  export LD_LIBRARY_PATH="$LIBC_DIR;$LD_LIBRARY_PATH"',
            '',
            '  # use system loader',
            '  ln -s ${LINKER_PATH} /tmp/appimage_$APPIMAGE_UUID.ld.so --force',
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

        file_lines.extend(self._generate_env_section())

        if self.env['LINKER_PATH']:
            file_lines.extend(self.sections['LINKER'])
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
            if v:
                line = 'export %s="%s"' % (k, v)
                lines.append(line)
        lines.append('')
        return lines

    def _set_permissions(self, path):
        os.chmod(path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP | stat.S_IXOTH | stat.S_IROTH)
