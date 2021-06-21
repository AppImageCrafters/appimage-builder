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

from appimagebuilder.context import AppInfo, BundleInfo
from appimagebuilder.modules.generate.bundle_info_gatherer import BundleInfoGatherer
from tests.modules.generate.fake_bundle_info_gatherer_ui import FakeBundleInfoGathererUi
from tests.modules.generate.fake_desktop_entry_parser import FakeDesktopEntryParser
from tests.modules.generate.fake_path import FakePath


class TestBundleInfoGatherer(TestCase):
    def setUp(self) -> None:
        self.expected_bundle_info = BundleInfo(
            app_info=AppInfo(
                id="fooview",
                name="Foo View",
                icon="fooview",
                exec="usr/bin/fooview",
                exec_args="$@",
            ),
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
        preset = "1.0.0"
        result = self.gatherer._confirm_application_version(preset)
        self.assertEqual(
            result,
            preset + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_version_empty(self):
        preset = ""
        result = self.gatherer._confirm_application_version(preset)
        self.assertEqual(
            result,
            "latest" + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_exec_args(self):
        preset = "$@"
        result = self.gatherer._confirm_application_exec_args(preset)
        self.assertEqual(
            result,
            "$@" + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_exec_args_empty(self):
        preset = ""
        result = self.gatherer._confirm_application_exec_args(preset)
        self.assertEqual(
            result,
            "$@" + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_exec_rel_path(self):
        preset = "app"
        fake_appdir = FakePath("/tmp/AppDir", ["/tmp/AppDir/usr/bin/app"])
        result = self.gatherer._confirm_application_exec(fake_appdir, preset)
        self.assertEqual(
            result,
            "usr/bin/app",
        )

    def test__confirm_application_exec_abs_path(self):
        preset = "/bin/app"
        fake_appdir = FakePath("/tmp/AppDir", ["/tmp/AppDir/bin/app"])
        result = self.gatherer._confirm_application_exec(fake_appdir, preset)
        self.assertEqual(
            result,
            preset + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_exec_no_preset(self):
        preset = ""
        result = self.gatherer._confirm_application_exec(
            FakePath("/tmp/AppDir", []), preset
        )
        self.assertEqual(
            result,
            FakeBundleInfoGathererUi.default_result,
        )

    def test__confirm_application_icon(self):
        preset = "app"
        result = self.gatherer._confirm_application_icon(preset)
        self.assertEqual(
            result,
            preset + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_name(self):
        preset = "App"
        result = self.gatherer._confirm_application_name(preset)
        self.assertEqual(
            result,
            preset + FakeBundleInfoGathererUi.edit_postfix,
        )

    def test__confirm_application_id_empty(self):
        preset = ""
        result = self.gatherer._confirm_application_id(preset)
        self.assertEqual(
            result,
            FakeBundleInfoGathererUi.default_result,
        )

    def test__confirm_application_id_preset(self):
        preset = "myapp"
        result = self.gatherer._confirm_application_id(preset)
        self.assertEqual(
            result,
            preset + FakeBundleInfoGathererUi.edit_postfix,
        )
