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

import unittest
from AppImageBuilder.AppDir.app_info.loader import AppInfoLoader, MissingConfigurationField


class LoaderTest(unittest.TestCase):
    def test_load_config(self):
        loader = AppInfoLoader()
        app_info = loader.load({
            'id': 'org.gnu.echo',
            'name': 'echo',
            'icon': 'utilities-terminal',
            'version': '2.7.1',
            "exec": "bin/echo",
            'exec_args': '$@'
        })

        self.assertEqual(app_info.id, 'org.gnu.echo')
        self.assertEqual(app_info.name, 'echo')
        self.assertEqual(app_info.icon, 'utilities-terminal')
        self.assertEqual(app_info.version, '2.7.1')
        self.assertEqual(app_info.exec, 'bin/echo')
        self.assertEqual(app_info.exec_args, '$@')

    def test_load_incomplete_config(self):
        app_info = AppInfoLoader()
        self.assertRaises(MissingConfigurationField, app_info.load,
                          {
                              'name': 'echo',
                              'icon': 'utilities-terminal',
                              'version': '2.7.1',
                              "exec": "bin/echo",
                              'exec_args': '$@'
                          })
