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

import unittest
from AppImageCraft.Configurator import Configurator, ConfigurationError


class ConfiguratorTests(unittest.TestCase):

    def test_load_empty(self):
        configurator = Configurator()

        self.assertRaises(ConfigurationError, configurator.load, "")

    def test_load_version(self):
        configurator = Configurator()
        recipe = '''
                version: 1
                App:
                    exec: usr/bin/echo
                AppDir:
                  path: ./AppDir
                '''
        configurator.load(recipe)
        self.assertEqual(configurator.version, 1)

    def test_load_version_failed(self):
        configurator = Configurator()
        recipe = '''
                blog: 1
                AppDir:
                  path: ./AppDir
                '''
        self.assertRaises(ConfigurationError, configurator.load, recipe)

    def test_load_unknown_version(self):
        configurator = Configurator()
        recipe = '''
                version: 4
                AppDir:
                  path: ./AppDir
                '''
        self.assertRaises(ConfigurationError, configurator.load, recipe)

    def test_load_app_dir_path(self):
        configurator = Configurator()
        recipe = '''
        version: 1
        App:
            exec: usr/bin/echo
        AppDir:
          path: ./AppDir
        '''
        builder = configurator.load(recipe)

        self.assertEqual(builder.app_dir_config['path'], "./AppDir")


if __name__ == '__main__':
    unittest.main()
