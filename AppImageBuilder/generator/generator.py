#!/usr/bin/env python3
#  Copyright 2020 Anupam Basak <anupam.basak27@gmail.com>
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
import questionary
import time
from emrichen import Context, Template
from progress.spinner import Spinner


class RecipeGenerator:
    def __init__(self):
        self.app_dir = ''
        self.app_info_id = ''
        self.app_info_name = ''
        self.app_info_icon = ''
        self.app_info_version = ''
        self.app_info_exec = ''
        self.app_info_exec_args = ''

        self.runtime_generator = ''
        self.runtime_env = []

        self.apt_arch = ''
        self.apt_sources = []
        self.apt_includes = []
        self.apt_excludes = []

        self.files_excludes = []

        self.appimage_arch = ''
        self.appimage_filename = ''

        self.setup_questions()

    def setup_questions(self):
        # AppDir -> app_info
        print('Basic Information :')
        self.app_info_id = questionary.text('ID [Eg: com.example.app] :').ask()
        self.app_info_name = questionary.text('Application Name :').ask()
        self.app_info_icon = questionary.text('Icon :').ask()
        self.app_info_version = questionary.text('Version :').ask()
        self.app_info_exec = questionary.text('Executable path relative to AppDir [usr/bin/app] :').ask()
        self.app_info_exec_args = questionary.text('Arguments [Default: $@] :', default='$@').ask()
        self.apt_arch = questionary.select('Architecture :', ['amd64', 'arm64']).ask()

        self.runtime_generator = questionary.select('Generator [Select `Wrapper` if unsure]',
                                                    ['wrapper', 'classic', 'proot']).ask()

        print('\nInput Environment Variables to be set while running the AppImage (One per line)')
        while True:
            env = questionary.text('Environment Variable [Eg: VAR=value] <Enter empty value to break> :').ask()

            if len(env.strip()) == 0:
                break

            self.runtime_env.append(env)
        print('')

        print('\nInput Apt Sources URLs (One per line) '
              '<Eg: deb http://archive.ubuntu.com/ubuntu/ bionic main>')

        while True:
            source_line = questionary.text('Apt source line <Enter empty value to break> :').ask()

            if len(source_line.strip()) == 0:
                break

            key_url = questionary.text(
                '    Public key url <Enter empty value if key is already added previously> :').ask()

            if len(key_url.strip()) == 0:
                self.apt_sources.append({'sourceline': source_line})
            else:
                self.apt_sources.append({
                    'sourceline': source_line,
                    'key_url': key_url
                })

        print('')
        spinner = Spinner('Fetching dependencies ')
        for i in range(50):
            spinner.next()
            time.sleep(0.1)
        spinner.finish()
        print('')

        add_packages_str = 'Add More Custom Packages'
        dependencies = ['p1', 'p2', 'p3', 'p4', add_packages_str]
        choices = questionary.checkbox('Dependencies', dependencies).ask()

        print('\nInput Extra Packages to be included in the AppDir (One per line)')
        if add_packages_str in choices:
            while True:
                package = questionary.text('Apt Package <Enter empty value to break> :').ask()

                if len(package.strip()) == 0:
                    break

                self.apt_includes.append(package)

            choices.remove(add_packages_str)
            self.apt_includes.extend(choices)

        print('\nInput Packages to be excluded from AppDir (One per line)')
        while True:
            package = questionary.text('Exclude Apt Package <Enter empty value to break> :').ask()

            if len(package.strip()) == 0:
                break

            self.apt_excludes.append(package)

        # AppDir -> files
        print('\nInput Files to be excluded from AppDir (One per line)')
        while True:
            file = questionary.text('File to be excluded form AppDir <Enter empty value to break> :').ask()

            if len(file.strip()) == 0:
                break

            self.files_excludes.append(file)

        # AppImage
        if self.apt_arch == 'amd64':
            self.appimage_arch = 'amd64'
        elif self.apt_arch == 'arm64':
            self.appimage_arch = 'aarch64'

        self.appimage_filename = questionary.text('AppImage File Name :').ask()

    def generate(self):
        appimage_builder_yml_template_path = os.path.realpath(os.path.join(
            os.path.dirname(__file__),
            'templates',
            'AppImageBuilder.yml.in'
        ))
        with open(appimage_builder_yml_template_path, 'r') as filedata:
            appimage_builder_yml_template = Template.parse(filedata, 'yaml')

        appimage_builder_yml_ctx = Context({
            'app_info_id': self.app_info_id,
            'app_info_name': self.app_info_name,
            'app_info_icon': self.app_info_icon,
            'app_info_version': self.app_info_version,
            'app_info_exec': self.app_info_exec,
            'app_info_exec_args': self.app_info_exec_args,

            'runtime_generator': self.runtime_generator,
            'runtime_env': self.runtime_env,

            'apt_arch': self.apt_arch,
            'apt_sources': self.apt_sources,
            'apt_includes': self.apt_includes,
            'apt_excludes': self.apt_excludes,

            'files_excludes': self.files_excludes,

            'appimage_arch': self.appimage_arch,
            'appimage_filename': self.appimage_filename
        })

        logging.debug(appimage_builder_yml_template.render(appimage_builder_yml_ctx))

