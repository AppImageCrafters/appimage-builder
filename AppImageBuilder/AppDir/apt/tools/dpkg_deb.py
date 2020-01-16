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


class DpkgDebError(RuntimeError):
    pass


class DpkgDeb:
    def extract(self, deb_file, target_dir):
        command = ["dpkg-deb", "-X", deb_file, target_dir]
        logging.debug(command)
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=target_dir)
        output = result.stdout.decode('utf-8')

        if result.returncode != 0:
            raise DpkgDebError("Package extraction failed. Error: " + result.stderr.decode('utf-8'))

        for line in output.splitlines():
            logging.info('%s: %s' % (os.path.basename(deb_file), line))
