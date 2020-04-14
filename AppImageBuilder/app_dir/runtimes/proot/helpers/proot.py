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
import subprocess

from AppImageBuilder.app_dir.runtimes.classic.helpers.base_helper import BaseHelper


class PRootError(RuntimeError):
    pass


class PRoot(BaseHelper):
    def configure(self, app_run):
        path = self._get_proot_path()
        if path:
            app_run.env['PROOT_PATH'] = '${APPDIR}/%s' % path
            app_run.env['PROOT_NO_SECCOMP'] = 1

            if self._is_statically_linked(path):
                app_run.sections['EXEC'] = [
                    '# Launch application using a fake root file system',
                    '${PROOT_PATH} -R ${APPDIR} -b /:/host_root -b /usr/share/icons -b /usr/share/mime '
                    '-b /etc/machine-id -b /etc/pulse -b /var/run -b /var/cache -b /var/lib/dbus '
                    '-w /host_root/$PWD /${BIN_PATH} ${EXEC_ARGS}',
                    ''
                ]
        else:
            raise PRootError('Unable to find proot binary')

    def _get_proot_path(self):
        return self._get_glob_relative_file_path('*/bin/proot')

    def _is_statically_linked(self, path):
        proc_env = os.environ.copy()
        proc_env['LC_ALL'] = 'LC_ALL=C.UTF-8'
        process = subprocess.run(['file', path], stdout=subprocess.PIPE, env=proc_env, cwd=self.app_dir)

        output = process.stdout.decode('utf-8')

        return 'statically linked' in output
