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

from appimagebuilder.generator.app_info import AppInfo
from appimagebuilder.generator.bundle_info import BundleInfo
from appimagebuilder.generator.bundle_info_gatherer import BundleInfoGatherer
from tests.generator.fake_bundle_info_gatherer_ui import FakeBundleInfoGathererUi
from tests.generator.fake_desktop_entry_parser import FakeDesktopEntryParser
from tests.generator.fake_path import FakePath


class TestBundleInfoGatherer(TestCase):
    def setUp(self) -> None:
        self.expected_bundle_info = BundleInfo(
            app_info=AppInfo(
                id="fooview",
                name="Foo View",
                icon="fooview",
                exec="usr/bin/fooview",
                exec_args="$@",
            )
        )

        self.entry_path = FakePath("/tmp/appdir/usr/share/applications/fooview.desktop")
        self.app_dir = FakePath("/tmp/appdir", [self.entry_path.path])

        self.gatherer = BundleInfoGatherer(
            FakeBundleInfoGathererUi(),
            FakeDesktopEntryParser(self.expected_bundle_info.app_info),
        )

    def tearDown(self) -> None:
        pass

    def test__search_desktop_entries(self):
        results = self.gatherer._search_desktop_entries(self.app_dir)
        self.assertIn(self.entry_path, results)

    def test__select_main_entry_none(self):
        self.assertRaises(RuntimeError, self.gatherer._select_main_entry, [])

    def test__select_main_entry_one(self):
        result = self.gatherer._select_main_entry(["b"])
        self.assertEqual(result, "b")

    def test__select_main_entry_many(self):
        result = self.gatherer._select_main_entry(["a", "b"])
        self.assertEqual(result, "b")

    def test__confirm_bundle_architecture(self):
        self.gatherer._confirm_bundle_architecture()
        self.assertEqual(
            self.gatherer._bundle_info.runtime_arch,
            "aarch64",
        )

    def test__confirm_bundle_update_information(self):
        self.gatherer._confirm_bundle_update_information()
        self.assertEqual(
            self.gatherer._bundle_info.update_string,
            "guess" + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_version(self):
        self.gatherer._bundle_info.app_info.version = "1.0.0"
        self.gatherer._confirm_application_version()
        self.assertEqual(
            self.gatherer._bundle_info.app_info.version,
            "1.0.0" + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_exec_args(self):
        self.gatherer._bundle_info.app_info.exec_args = "$@"
        self.gatherer._confirm_application_exec_args()
        self.assertEqual(
            self.gatherer._bundle_info.app_info.exec_args,
            "$@" + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_exec(self):
        self.gatherer._bundle_info.app_info.exec = "bin/app"
        self.gatherer._confirm_application_exec()
        self.assertEqual(
            self.gatherer._bundle_info.app_info.exec,
            "bin/app" + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_icon(self):
        self.gatherer._bundle_info.app_info.icon = "app"
        self.gatherer._confirm_application_icon()
        self.assertEqual(
            self.gatherer._bundle_info.app_info.icon,
            "app" + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_name(self):
        self.gatherer._bundle_info.app_info.name = "App"
        self.gatherer._confirm_application_name()
        self.assertEqual(
            self.gatherer._bundle_info.app_info.name,
            "App" + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_id_empty(self):
        self.gatherer._confirm_application_id()
        self.assertEqual(
            self.gatherer._bundle_info.app_info.id,
            FakeBundleInfoGathererUi.default_result,
        )

    def test__confirm_application_id_preset(self):
        self.gatherer._bundle_info.app_info.id = "myapp"
        self.gatherer._confirm_application_id()
        self.assertEqual(
            self.gatherer._bundle_info.app_info.id,
            "myapp",
        )
