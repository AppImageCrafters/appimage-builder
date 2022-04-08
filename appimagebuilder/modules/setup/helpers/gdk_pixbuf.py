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
import re
import subprocess
import shutil

from appimagebuilder.utils.finder import Finder
from .base_helper import BaseHelper
from ..environment import Environment


class GdkPixbuf(BaseHelper):
    def configure(self, env: Environment, preserve_files):
        loaders_dir_path = self.finder.find_one(
            "*/gdk-pixbuf-2.0/*/loaders", [Finder.is_dir]
        )
        if loaders_dir_path:
            base_dir = os.path.dirname(loaders_dir_path)
            loaders_cache_path = os.path.join(base_dir, "loaders.cache")

            logging.info("GDK loaders cache modules dir: %s" % loaders_cache_path)
            self._generate_loaders_cache(loaders_cache_path)

            env.set("GDK_PIXBUF_MODULEDIR", loaders_dir_path)
            env.set("GDK_PIXBUF_MODULE_FILE", loaders_cache_path)

    def _generate_loaders_cache(self, loaders_cache_path):
        bin_path = self._find_gdk_pixbuf_query_loaders_bin()

        logging.warning(
            "gdk-pixbuf-query-loaders cannot generate cache from modules of a "
            "different version or architecture. Therefore it will be ran using the"
            "system modules and the output will be *adapted* to the AppDir."
        )

        proc = subprocess.run(bin_path, stdout=subprocess.PIPE)

        query_output = proc.stdout.decode()
        # remove absolute paths from module names
        query_output = re.sub(r"\"(/.*/)(.+)\"\n", r'"\2"\n', query_output)

        with open(loaders_cache_path, "w") as f:
            f.write(query_output)

        logging.info("GDK loaders cache wrote to: %s" % loaders_cache_path)

    @staticmethod
    def _find_gdk_pixbuf_query_loaders_bin():
        for root, dirs, files in os.walk("/usr/lib"):
            if "gdk-pixbuf-query-loaders" in files:
                return os.path.join(root, "gdk-pixbuf-query-loaders")
        # we did not find gdk-pixbuf-query-loaders in /usr/lib
        # perhaps we should search /usr/bin too
        # Arch Linux has gdk-pixbuf-query-loaders in /usr/bin and
        # not in /usr/lib. This can be easily found out using
        # shutil.which API. => $PATH
        if shutil.which("gdk-pixbuf-query-loaders"):
            return shutil.which("gdk-pixbuf-query-loaders")
        # fedora provides gdk-pixbuf-query-loaders-64 instead
        # of gdk-pixbuf-query-loaders in /usr/bin
        if shutil.which("gdk-pixbuf-query-loaders-64"):
            return shutil.which("gdk-pixbuf-query-loaders-64")

        raise RuntimeError(
            "Missing 'gdk-pixbuf-query-loaders' "
            "or 'gdk-pixbuf-query-loaders-64' executable"
        )

    def _remove_loaders_path_prefixes(self, loaders_cache):
        output = []
        for line in loaders_cache:
            if line.startswith('"/'):
                line = line.strip('"')
                line = os.path.basename(line)
                line = '"%s"' % line

            output.append(line)

        return output
