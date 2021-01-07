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
import logging
import re
import subprocess

from packaging import version

from .base_helper import BaseHelper


class LinuxABIReader(BaseHelper):
    def configure(self, app_run):
        paths = self.app_dir_cache.find("*", attrs=["is_elf"])
        max_abi = version.parse("0.0.0")
        for path in paths:
            _proc = subprocess.run(["readelf", "--notes", path], stdout=subprocess.PIPE)
            results = _proc.stdout.decode("utf-8")
            match = re.search(r"ABI:\s(?P<abi>(\d|.)+)", results, re.MULTILINE)
            if match:
                new_abi_version = version.parse(match.group('abi'))
                if new_abi_version > max_abi:
                    max_abi = new_abi_version

        app_run.env["LINUX_ABI"] = str(max_abi)
        logging.warning("Minimun Linux ABI required: %s" % max_abi)
