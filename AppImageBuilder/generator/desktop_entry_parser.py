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

import configparser
import os


class DesktopFileParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.parser = configparser.ConfigParser()
        self.parser.read(file_path)

        exec = self.parser['Desktop Entry']['Exec'].strip()
        self.exec_path, self.exec_args = self._split_exec_path_and_args(exec)

        # convert desktop file exec args to bash notation
        self.exec_args = self.exec_args.replace('%f', '$@')
        self.exec_args = self.exec_args.replace('%F', '$@')
        self.exec_args = self.exec_args.replace('%U', '$@')
        self.exec_args = self.exec_args.replace('%u', '$@')

    @staticmethod
    def _split_exec_path_and_args(exec):
        if exec[0] == '\'' or exec[0] == '\"':
            end = exec.find(exec[0], 1)
            while end != -1 and exec[end - 1] == '\\':
                end = exec.find(exec[0], end + 1)
            if end == -1:
                end = len(exec)

            exec_path = exec[1:end].strip()
            exec_args = exec[end + 1:].strip()

            return exec_path, exec_args
        else:
            end = exec.find(" ")
            if end == -1:
                end = len(exec)

            exec_path = exec[:end].strip()
            exec_args = exec[end + 1:].strip()

            return exec_path, exec_args

    def get_name(self):
        return self.parser['Desktop Entry']['Name']

    def get_icon(self):
        return self.parser['Desktop Entry']['Icon']

    def get_exec_path(self):
        return self.exec_path

    def get_exec_args(self):
        return self.exec_args

    def get_id(self):
        filename, file_extension = os.path.splitext(os.path.basename(self.file_path))
        return filename
