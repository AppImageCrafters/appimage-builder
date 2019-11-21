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
import os
import re
import subprocess


class LinkerTool:

    def __init__(self, binary_path=None):
        self.logger = logging.getLogger("LinkerTool")
        if not binary_path:
            self.binary_path = self.find_binary_path("/")
        else:
            self.binary_path = binary_path

    @staticmethod
    def find_binary_path(prefix: str) -> str:
        linker_dirs = [os.path.join(prefix, "lib", "x86_64-linux-gnu")]

        for linker_dir in linker_dirs:
            logging.debug("Looking linker binary at: %s\n" % linker_dir)
            for root, dirs, files in os.walk(linker_dir):
                for file_name in files:
                    if file_name.startswith('ld-') and file_name.endswith('.so'):
                        return os.path.join(root, file_name)

        return ''

    def list_link_dependencies(self, file, ignore_cache=False, library_dirs=None):
        result = self._execute_ld_so_command(file, ignore_cache, library_dirs)
        if result.returncode == 0:
            return self._parse(result.stdout.decode('utf-8'))
        else:
            self.logger.error("Dependencies lockup failed: %s" % result.stderr.decode('utf-8'))

    def _execute_ld_so_command(self, file, ignore_cache, library_dirs):
        command = [self.binary_path]
        if ignore_cache:
            command.append("--inhibit-cache")
        if library_dirs:
            command.append("--library-path")
            command.append("\"%s\"" % ":".join(library_dirs))
        command.append("--list")
        command.append(file)

        self.logger.debug(" ".join(command))

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result

    def list_linkable_files(self, root_dir):
        linkable_files = []

        for root, dirs, files in os.walk(root_dir):
            for filename in files:
                full_path = os.path.join(root, filename)
                if self.linkable(full_path):
                    linkable_files.append(full_path)

        return linkable_files

    def linkable(self, full_path):
        result = subprocess.run([self.binary_path, "--verify", full_path])
        return result.returncode == 2 or result.returncode == 0

    def list_libraries_files(self, root_dir):
        library_files = []

        for root, dirs, files in os.walk(root_dir):
            for filename in files:
                full_path = os.path.join(root, filename)
                result = subprocess.run([self.binary_path, "--verify", full_path])
                if result.returncode == 2:
                    library_files.append(full_path)

        # print("Library Files found: \n\t%s\n" % "\n\t".join(library_files) )
        return library_files

    def list_runnable_files(self, root_dir):
        binary_files = []

        for root, dirs, files in os.walk(root_dir):
            for filename in files:
                full_path = os.path.join(root, filename)
                result = subprocess.run([self.binary_path, "--verify", full_path])
                if result.returncode == 0:
                    binary_files.append(full_path)

        # print("Runnable Files found: \n\t%s\n" % "\n\t".join(binary_files) )
        return binary_files

    def _parse(self, output):
        results = {}
        for line in output.splitlines():
            if "statically linked" in line:
                continue

            line = self._remove_output_line_memory_address(line.strip(" "))

            if '=>' in line:
                line_parts = line.split('=>')
                results[line_parts[0].strip()] = line_parts[1].strip()
            else:
                results[line] = None

        return results

    @staticmethod
    def _remove_output_line_memory_address(line):
        line = re.sub(r'\(.*\)', '', line)
        return line.strip()
