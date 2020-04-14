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

from .factory import BundlerFactory
from .bundler import Bundler


class BundlerFactoryTestCase(unittest.TestCase):
    class DummyBundler(Bundler):
        def __init__(self, config):
            super().__init__(config)
            self.config_validated = False
            self.run_executed = True

            self.wrapper_apprun_packages = ['wrapper']
            self.proot_apprun_packages = ['proot']
            self.classic_apprun_packages = ['classic']
            self.core_packages = ['core']
            self.font_config_packages = ['fontconfig']
            self.graphics_stack_packages = ['graphics']
            self.xclient_packages = ['xclient']

        def validate_configuration(self):
            self.config_validated = True

        def run(self):
            self.run_executed = True

    def setUp(self) -> None:
        self.factory = BundlerFactory('/', '/tmp')
        self.factory.bundlers = {'dummy': BundlerFactoryTestCase.DummyBundler}

    def test_list_bundlers(self):
        self.assertEqual(['dummy'], list(self.factory.list_bundlers()))

    def test_create_bundler_for_classic_type_runtime(self):
        self.factory.runtime = 'classic'
        bundler = self.factory.create('dummy', [])

        self.assertTrue(bundler.config_validated)
        self.assertEqual(bundler.app_dir, self.factory.app_dir)
        self.assertEqual(bundler.cache_dir, self.factory.cache_dir)

        self.assertEqual(bundler.included_packages, [*bundler.classic_apprun_packages])
        self.assertEqual(bundler.excluded_packages, [*bundler.core_packages])

        self.assertEqual(bundler.partitions, {})

    def test_create_bundler_for_proot_type_runtime(self):
        self.factory.runtime = 'proot'
        bundler = self.factory.create('dummy', [])

        self.assertTrue(bundler.config_validated)
        self.assertEqual(bundler.app_dir, self.factory.app_dir)
        self.assertEqual(bundler.cache_dir, self.factory.cache_dir)

        self.assertEqual(bundler.included_packages, bundler.proot_apprun_packages)
        self.assertEqual(bundler.excluded_packages, [*bundler.core_packages])

        self.assertEqual(bundler.partitions, {})

    def test_create_bundler_for_wrapper_type_runtime(self):
        self.factory.runtime = 'wrapper'
        bundler = self.factory.create('dummy', [])

        self.assertTrue(bundler.config_validated)
        self.assertEqual(bundler.app_dir, self.factory.app_dir)
        self.assertEqual(bundler.cache_dir, self.factory.cache_dir)

        self.assertEqual(bundler.included_packages, bundler.wrapper_apprun_packages)
        self.assertEqual(bundler.excluded_packages, [*bundler.core_packages, *bundler.font_config_packages,
                                                     *bundler.graphics_stack_packages, *bundler.xclient_packages])

        self.assertEqual(bundler.partitions, {'opt/libc': bundler.glibc_packages})

    def test_run(self):
        bundler = self.factory.create('dummy', [])
        bundler.run()
        self.assertTrue(bundler.run_executed)