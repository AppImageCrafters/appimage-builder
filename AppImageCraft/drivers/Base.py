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
import shutil


class Dependency:
    driver = None
    source = None
    target = None
    deployed = False

    def __init__(self, driver=None, source=None, target=None):
        self.driver = driver
        self.source = source
        self.target = target

    def deploy(self, app_dir):
        self.driver.deploy(self, app_dir)

    def __str__(self):
        return "(%s, %s, %s)" % (self.driver.id, self.source, self.target)

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, Dependency):
            # don't attempt to compare against unrelated types
            return False

        return self.driver == o.driver and self.source == o.source and self.target == o.target and self.deployed == o.deployed


class Driver:
    """Assist on identifying and deploying file dependencies"""
    id = None

    def lockup_dependencies(self, file):
        pass

    def deploy(self, dependency, app_dir):
        dependency.target = app_dir.path + dependency.source

        os.makedirs(os.path.dirname(dependency.target), exist_ok=True)

        shutil.copy2(dependency.source, dependency.target)

        dependency.deployed = True

    def __str__(self) -> str:
        return self.id


