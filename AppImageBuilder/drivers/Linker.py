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

from AppImageBuilder import drivers
from AppImageBuilder import tools


class LinkerDependency(drivers.Dependency):
    soname = None

    def __init__(self, driver=None, source=None, target=None, soname=None):
        super().__init__(driver, source, target)

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, LinkerDependency):
            # don't attempt to compare against unrelated types
            return False

        return super().__eq__(o) and self.soname == o.soname

    def __str__(self):
        return super().__str__()


class Linker(drivers.Driver):
    id = 'linker'
    linker = None

    def __init__(self):
        self.linker = tools.Linker()

    def lockup_file_dependencies(self, file, app_dir):
        dependencies = []
        if not self.linker.linkable(file):
            return None

        linker_map = self.linker.list_link_dependencies(file)
        if linker_map:
            for k, v in linker_map.items():
                if v and not app_dir.bundled(v):
                    dependencies.append(LinkerDependency(self, v, None, k))

        return dependencies

    def configure(self, app_dir):
        self._set_app_run_ld_library_dirs_env(app_dir)

        app_dir.app_run.env['LINKER_PATH'] = "$APPDIR" + self.linker.binary_path

    def _set_app_run_ld_library_dirs_env(self, app_dir):
        elf_file_paths = self.linker.list_libraries_files(app_dir.path)
        elf_dirs_paths = {os.path.dirname(file) for file in elf_file_paths}
        relative_elf_dir_paths = {dir.replace(app_dir.path, '').lstrip('/') for dir in elf_dirs_paths}
        ld_library_path_entries = {"${APPDIR}/%s" % dir for dir in relative_elf_dir_paths}

        app_dir.app_run.env['LD_LIBRARY_DIRS'] = ":".join(ld_library_path_entries)
