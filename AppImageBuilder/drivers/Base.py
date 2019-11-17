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
import logging


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
    config = {}
    _logger = None

    def load_config(self, config):
        self.config = config

    def list_base_dependencies(self, app_dir):
        pass

    def lockup_file_dependencies(self, file, app_dir):
        pass

    def deploy(self, dependency, app_dir):
        dependency.target = app_dir.path + dependency.source
        self.logger().info("Deploying %s to %s" % (dependency.source, dependency.target))
        try:
            os.makedirs(os.path.dirname(dependency.target), exist_ok=True)
            shutil.copy2(dependency.source, dependency.target)
        except FileNotFoundError as error:
            raise RuntimeError('Unable to deploy %s. %s' % (dependency, error))
        except NotADirectoryError as error:
            raise RuntimeError('Unable to deploy %s. %s' % (dependency, error))
        dependency.deployed = True

    def configure(self, app_dir):
        pass

    def __str__(self) -> str:
        return self.id

    def logger(self):
        if not self._logger:
            self._logger = logging.getLogger(self.id)

        return self._logger
