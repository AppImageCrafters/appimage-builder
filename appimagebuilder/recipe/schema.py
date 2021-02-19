#   Copyright  2020 Alexis Lopez Zubieta
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#   sell copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.


from schema import Schema, And, Optional, Or


class RecipeSchema:
    def __init__(self):
        self.version = Schema(int, ignore_extra_keys=True)
        self.script = Schema(Or(str, [str]))

        self.v1_app_info = {
            "id": str,
            "name": str,
            "icon": str,
            "version": str,
            "exec": str,
            Optional("exec_args"): str,
        }

        self.v1_files = {
            Optional("include"): [str],
            Optional("exclude"): [str],
        }

        self.v1_runtime = {
            Optional("debug"): bool,
            Optional("version"): str,
            Optional("path_mappings"): [str],
            Optional("env"): {str: Or(str, int, bool)},
        }

        self.v1_tests = {
            str: {
                "image": str,
                "command": str,
                Optional("use_host_x"): bool,
                Optional("env"): {str: Or(str, int, bool)},
            }
        }

        self.v1_apt = Schema(
            {
                "arch": Or(str, [str]),
                "sources": [{"sourceline": str, Optional("key_url"): str}],
                "include": [str],
                Optional("exclude"): [str],
                Optional("allow_unauthenticated"): bool,
            }
        )
        self.v1_pacman = Schema(
            {
                Optional("Architecture"): Or("auto", "x86_64", "i686", "aarch64"),
                Optional("SigLevel"): Or("Never", "Optional", "Required"),
                Optional("repositories"): {str: [str]},
                "include": [str],
                Optional("exclude"): [str],
            }
        )

        self.v1_appdir = Schema(
            {
                "path": str,
                "app_info": self.v1_app_info,
                Optional("files"): self.v1_files,
                Optional("apt"): self.v1_apt,
                Optional("pacman"): self.v1_pacman,
                Optional("runtime"): self.v1_runtime,
                Optional("test"): self.v1_tests,
                Optional("before_bundle"): self.script,
                Optional("after_bundle"): self.script,
                Optional("before_runtime"): self.script,
                Optional("after_runtime"): self.script,
            }
        )

        self.v1_appimage = Schema(
            {
                "arch": str,
                Optional("update-information"): str,
                Optional("sign-key"): str,
                Optional("file_name"): str,
            }
        )

        self.v1 = Schema(
            {
                "version": int,
                Optional("script"): self.script,
                "AppDir": self.v1_appdir,
                "AppImage": self.v1_appimage,
            }
        )
