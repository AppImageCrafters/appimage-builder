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
import subprocess

from .base_helper import BaseHelper


class GdkPixbuf(BaseHelper):

    def configure(self, app_run):
        path = self._get_gdk_pixbuf_loaders_path()
        if path:
            loaders_cache_path = os.path.join(self.app_dir, os.path.dirname(path), 'loaders.cache')

            self._generate_loaders_cache(path, loaders_cache_path)

            app_run.env['GDK_PIXBUF_MODULEDIR'] = '$APPDIR/%s' % path
            app_run.env['GDK_PIXBUF_MODULE_FILE'] = loaders_cache_path.replace(self.app_dir, '$APPDIR')
            app_run.env['APPDIR_LIBRARY_PATH'] = '$APPDIR/%s:%s' % (path, app_run.env['APPDIR_LIBRARY_PATH'])

    def _generate_loaders_cache(self, loaders_path, loaders_cache_path):
        proc = subprocess.run(['gdk-pixbuf-query-loaders'], cwd=self.app_dir, stdout=subprocess.PIPE)
        query_output = proc.stdout.decode('utf-8')

        logging.info("GDK loaders cache modules dir: %s" % loaders_path)
        modified_output = self._remove_loaders_path_prefixes(query_output.splitlines())

        with open(loaders_cache_path, 'w') as f:
            f.write('\n'.join(modified_output))

        logging.info("GDK loaders cache wrote to: %s" % loaders_cache_path)

    def _get_gdk_pixbuf_loaders_path(self):
        return self._get_glob_relative_sub_dir_path('*/usr/*/gdk-pixbuf-2.0/*/loaders/*')

    def _remove_loaders_path_prefixes(self, loaders_cache):
        output = []
        for line in loaders_cache:
            if line.startswith('"/'):
                line = line.strip('"')
                line = os.path.basename(line)
                line = '"%s"' % line

            output.append(line)

        return output
