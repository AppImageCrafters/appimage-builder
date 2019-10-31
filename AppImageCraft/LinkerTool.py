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

import os
import lief
import subprocess

class LinkerTool:

    def __init__(self, binary_path=""):
        self.binary_path = binary_path

        if not self.binary_path and os.path.exists("/lib/x86_64-linux-gnu/ld-2.27.so"):
            self.binary_path = "/lib/x86_64-linux-gnu/ld-2.27.so"

        if not self.binary_path and os.path.exists("/lib/i386-linux-gnu/ld-2.27.so"):
            self.binary_path = "/lib/i386-linux-gnu/ld-2.27.so"

    def list_link_dependencies(self, file):
        dependencies = set()
        missing = set()
        result = subprocess.run([self.binary_path, "--list", file], stdout=subprocess.PIPE)
        output = result.stdout.decode('utf-8')

        for line in output.splitlines():
            line_parts = line.strip().split(" ")
            if len(line_parts) > 2:
                dependencies.add(line_parts[2])
            else:
                missing.add(line_parts[0])

        missing.remove("linux-vdso.so.1")
        return (dependencies, missing)

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

    def update_run_paths(self):
        elf_files = self._locate_elf_files()
        ld_paths = sorted(self._generate_run_paths(elf_files))

        print("Updating run paths to:")
        for path in ld_paths:
            print("\t%s" % path)

        for file in elf_files:
            # Don't modify the linker
            if "ld-" in file and (file.endswith(".so") or file.endswith(".so.2")):
                # FileUtils.replace_in_file(file, b"/usr/", b"/xxx/")
                print("skip linker %s" % file)
                continue

            binary = lief.parse(file)

            try:
                runpath_entry = binary.get(tag=lief.ELF.DYNAMIC_TAGS.RUNPATH)
                if ld_paths != runpath_entry.paths:
                    runpath_entry.paths = ld_paths
                    binary.write(file)
                    print("run path entry updated for: %s" % file)
            except:
                runpath_entry = lief.ELF.DynamicEntryRunPath(ld_paths)
                binary.add(runpath_entry)
                binary.write(file)
                print("run path entry created for: %s" % file)

    def _locate_elf_files(self):
        elf_files = []
        for root, dirs, files in os.walk(self.appdir_path):
            for filename in files:
                full_path = os.path.join(root, filename)
                binary = lief.parse(full_path)
                if binary:
                    elf_files.append(full_path)

        return elf_files


    def _generate_run_paths(self, elf_files):
        run_paths = set()
        binary_dir = os.path.join(self.appdir_path, os.path.dirname(self.app_runnable))
        for file in elf_files:
            dir_name = os.path.dirname(file)
            relative_path = os.path.relpath(dir_name, binary_dir)
            run_paths.add("$ORIGIN/%s" % relative_path)

        return list(run_paths)