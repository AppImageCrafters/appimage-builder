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
import os
import pathlib

from appimagebuilder.recipe import Roamer
from appimagebuilder.utils.finder import Finder
from appimagebuilder.commands.command import Command


class SetupSymlinksCommand(Command):
    def __init__(self, context, recipe: Roamer, finder: Finder):
        super().__init__(context, "symlinks setup")
        self._finder = finder

        self._preserve_files = []
        base_paths = [
            self._finder.base_path,
            self._finder.base_path / "runtime" / "compat",
        ]
        preserve_paths = recipe.AppDir.runtime.preserve() or []
        for pattern in preserve_paths:
            for base_path in base_paths:
                for match in base_path.glob(pattern):
                    if match.is_dir():
                        self._preserve_files.extend(match.glob("**/*"))
                    else:
                        self._preserve_files.append(match)

    def id(self):
        return "symlinks-setup"

    def __call__(self, *args, **kwargs):
        for link in self._finder.find("*", [Finder.is_symlink]):
            allowed = True
            for preserve_file in self._preserve_files:
                if preserve_file.samefile(link):
                    allowed = False
                    break
            if allowed:
                relative_root = (
                    self.context.app_dir
                    if "runtime/compat" not in str(link)
                    else self.context.app_dir / "runtime" / "compat"
                )
                self._make_symlink_relative(link, relative_root)

    @staticmethod
    def _make_symlink_relative(path, relative_root):
        path = pathlib.Path(path)
        relative_root = pathlib.Path(relative_root)

        if path.is_symlink():
            target = pathlib.Path(os.readlink(path))
            if target.is_absolute():
                # workaround issue with concatenating paths using the "/" operator
                new_target = str(relative_root) + str(target)
                new_target = os.path.relpath(new_target, path.parent)

                path.unlink()
                path.symlink_to(new_target)
