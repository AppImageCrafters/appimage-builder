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

import schema

from AppImageBuilder.app_dir.bundlers.apt.settings_validator import AptSettingsValidator


class AptSettingsValidatorTestCase(unittest.TestCase):
    def test_validate_broken_sources(self):
        validator = AptSettingsValidator({
            'arch': 'i386',
            'sources': [
                {'as': 'asd'}
            ],
            'include': [],
        })

        self.assertRaises(schema.SchemaError, validator.validate)

    def test_validate_missing_include(self):
        validator = AptSettingsValidator({
            'arch': 'i386',
            'sources': [],

        })

        self.assertRaises(schema.SchemaError, validator.validate)

    def test_validate_correct(self):
        validator = AptSettingsValidator({
            'arch': 'i386',
            'sources': [
                {
                    'sourceline': 'deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ bionic main restricted universe multiverse',
                    'key_url': 'http://archive.neon.kde.org/public.key'
                }
            ],
            'include': ['package']
        })

        validator.validate()
