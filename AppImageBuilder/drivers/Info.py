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

from AppImageBuilder import drivers
from AppImageBuilder.DesktopEntryBuilder import DesktopEntryBuilder


class Info(drivers.Driver):
    id = 'info'

    def configure(self, app_dir):
        self._generate_desktop_entry(app_dir)
        self._copy_icon_from_theme(app_dir)

    def _generate_desktop_entry(self, app_dir):
        self.logger().debug("Generating desktop entry.")

        desktop_entry_builder = DesktopEntryBuilder()

        desktop_entry_builder.app_id = self.config['id']
        desktop_entry_builder.app_name = self.config['name']
        desktop_entry_builder.app_icon = self.config['icon']
        desktop_entry_builder.app_version = self.config['version']
        desktop_entry_builder.app_categories = self.config['categories'] if 'categories' in self.config else ["Utility"]
        desktop_entry_builder.app_summary = self.config['summary'] if 'summary' in self.config else ''

        path = os.path.join(app_dir.path, desktop_entry_builder.get_file_name())
        desktop_entry_builder.generate(path)
        self.logger().info("Writing Desktop Entry to: %s" % path)

    def _copy_icon_from_theme(self, app_dir):
        app_icon = self.config['icon']
        self.logger().info("Importing icon '%s' from system theme" % app_icon)

        icon_path = None
        icon_path = self._search_icon(app_icon, app_dir.path + "/usr/share/icons")
        if not icon_path:
            icon_path = self._search_icon(app_icon, "/usr/share/icons")

        if not icon_path:
            raise RuntimeError('Icon not found in system')

        target_icon_path = os.path.join(os.path.abspath(app_dir.path), os.path.basename(icon_path))
        self.logger().info("Coping: '%s' to '%s'" % (icon_path, target_icon_path))
        shutil.copyfile(icon_path, target_icon_path)

    def _search_icon(self, app_icon, search_path):
        icon_path = None
        self.logger().info("Looking app icon at: %s" % search_path)
        for root, dirs, files in os.walk(search_path):
            for filename in files:
                if app_icon in filename:
                    icon_path = os.path.join(root, filename)

        return icon_path
