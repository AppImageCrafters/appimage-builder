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
import logging
import os
import platform


class DesktopEntryGenerator:
    class Error(RuntimeError):
        pass

    def __init__(self, app_dir):
        self._desktop_entry_header = '[Desktop Entry]\n'
        self.contents = []
        self.app_dir = app_dir

    def generate(self, app_info):
        try:
            self._load_app_desktop_entry(app_info.id)
        except DesktopEntryGenerator.Error as err:
            logging.warning(err)
            self.contents = self._generate_minimal_desktop_entry(app_info)

        self._add_appimage_name(app_info.name)
        self._add_appimage_version(app_info.version)
        self._add_appimage_arch(platform.machine())

        self._save_app_dir_desktop_entry(app_info.id)

    def _match_desktop_entry(self, app_id, file_name):
        return (app_id + '.desktop') in file_name

    def _add_appimage_name(self, name):
        idx = self._get_desktop_entry_header_index()
        self.contents.insert(idx + 1, 'X-AppImage-Name=%s\n' % name)

    def _get_desktop_entry_header_index(self):
        if self._desktop_entry_header in self.contents:
            return self.contents.index(self._desktop_entry_header)
        else:
            raise DesktopEntryGenerator.Error('Unable to locate the desktop entry header')

    def _add_appimage_version(self, version):
        idx = self._get_desktop_entry_header_index()
        self.contents.insert(idx + 1, 'X-AppImage-Version=%s\n' % version)

    def _add_appimage_arch(self, arch):
        idx = self._get_desktop_entry_header_index()
        self.contents.insert(idx + 1, 'X-AppImage-Arch=%s\n' % arch)

    def _add_appimage_entries(self):
        self._add_appimage_name('Ark')
        self._add_appimage_version('0.1')
        self._add_appimage_arch('amd64')

    def _load_app_desktop_entry(self, app_id):
        desktop_entry_path = self._find_app_desktop_entry_path(self.app_dir, app_id)

        with open(desktop_entry_path, 'r', encoding='utf-8') as f:
            self.contents = f.readlines()

    def _find_app_desktop_entry_path(self, app_dir, app_id):
        apps_dir = os.path.join(app_dir, 'usr', 'share', 'applications')
        try:
            for file_name in os.listdir(apps_dir):
                if self._match_desktop_entry(app_id, file_name):
                    return os.path.join(apps_dir, file_name)
        except FileNotFoundError:
            raise DesktopEntryGenerator.Error('Unable to locate the application desktop entry: %s.desktop' % app_id)

        raise DesktopEntryGenerator.Error('Unable to locate the application desktop entry: %s.desktop' % app_id)

    def _save_app_dir_desktop_entry(self, app_id):
        file_name = os.path.join(self.app_dir, app_id + '.desktop')

        with open(file_name, 'w', encoding='utf-8') as f:
            f.writelines(self.contents)

    def _generate_minimal_desktop_entry(self, app_info):
        return [
            '[Desktop Entry]\n',
            'Name=%s\n' % app_info.name,
            'Exec=%s\n' % app_info.exec,
            'Icon=%s\n' % app_info.icon,
            'Type=Application\n',
            'Terminal=false\n',
            'Categories=Utility;\n',
            'Comment=\n'
        ]
