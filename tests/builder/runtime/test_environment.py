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

from unittest import TestCase

from appimagebuilder.modules.setup.environment import Environment


class TestEnvironment(TestCase):
    def test_serialize(self):
        env = Environment(
            {
                "APPDIR": "$ORIGIN/..",
                "APPIMAGE_UUID": "123",
                "APPDIR_EXEC_ARGS": ["-f", "$@"],
                "LIST": ["1", "2"],
                "DICT": {
                    "a": "b",
                    "c": "d",
                },
                "APPDIR_LIBRARY_PATH": ["/AppDir/usr/lib"],
                "APPDIR_PATH_MAPPINGS": ["a:b", "c:d"],
                "NONE": None,
            }
        )
        result = env.serialize()

        expected = (
            "APPDIR=$ORIGIN/..\n"
            "APPIMAGE_UUID=123\n"
            "APPDIR_EXEC_ARGS=-f $@\n"
            "LIST=1:2\n"
            "DICT=a:b;c:d;\n"
            "APPDIR_LIBRARY_PATH=/AppDir/usr/lib\n"
            "APPDIR_PATH_MAPPINGS=a:b;c:d;\n"
            'NONE=""\n'
        )

        self.assertEqual(expected, result)
