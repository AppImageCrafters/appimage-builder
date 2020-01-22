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


import logging
import subprocess


class GenerateAppImageCommand:
    def __init__(self, app_dir):
        self.app_dir = app_dir
        self.runtime_file = None
        self.update_information = None
        self.sign_key = None

    def run(self, target_file):
        logging.info("Generating AppImage from %s" % self.app_dir)
        command = self._generate_command(target_file)
        logging.info(' '.join(command))

        result = subprocess.run(command)
        if result.returncode != 0:
            logging.error("AppImage generation failed")
        else:
            logging.info(result.stdout)
            logging.info("AppImage created successfully")

    def _generate_command(self, target_file):
        command = ["appimagetool"]
        if self.runtime_file:
            command.extend(['--runtime-file', self.runtime_file])
        if self.sign_key:
            command.extend(['--sign-key', self.sign_key])
        if self.update_information:
            command.extend(['--updateinformation', self.update_information])
        command.extend([self.app_dir, target_file])
        return command
