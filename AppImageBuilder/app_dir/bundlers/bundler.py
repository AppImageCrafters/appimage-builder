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
import os


class Bundler:
    def __init__(self, settings):
        self.settings = settings

        self.app_dir = None
        self.cache_dir = None
        self.partitions = {}
        self.excluded_packages = []
        self.included_packages = []

        # default package lists
        self.core_packages = []
        self.font_config_packages = []
        self.xclient_packages = []
        self.graphics_stack_packages = []
        self.glibc_packages = []

        #   packages required by the runtime generators
        self.proot_apprun_packages = []
        self.wrapper_apprun_packages = []
        self.classic_apprun_packages = []

    def validate_configuration(self):
        pass

    def run(self):
        pass

    def _resolve_partition_path(self, package_name, app_dir_path):
        for name, packages in self.partitions.items():
            if package_name in packages:
                return os.path.join(app_dir_path, name)

        return app_dir_path
