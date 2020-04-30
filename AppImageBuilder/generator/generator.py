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
import shutil

import questionary
from emrichen import Context, Template

from AppImageBuilder.commands.file import File
from AppImageBuilder.generator.app_runtime_analyser import AppRuntimeAnalyser
from AppImageBuilder.generator.apt_recipe_generator import AptRecipeGenerator
from AppImageBuilder.generator.desktop_entry_parser import DesktopFileParser


class RecipeGeneratorError(RuntimeError):
    pass


class RecipeGenerator:
    def __init__(self):
        self.logger = logging.getLogger("Generator")

        self.logger.info("Searching AppDir")
        self.app_dir = self._locate_app_dir()
        self.app_info_id = ''
        self.app_info_name = ''
        self.app_info_icon = ''
        self.app_info_version = 'latest'
        self.app_info_exec = ''
        self.app_info_exec_args = '$@'

        self.runtime_generator = None
        self.runtime_env = None
        self.appimage_arch = None

        self.apt_arch = None
        self._setup_app_info()
        self.setup_questions()

        self.logger.info("Analysing application runtime dependencies")
        runtime_analyser = AppRuntimeAnalyser(self.app_dir, self.app_info_exec, self.app_info_exec_args)
        runtime_analyser.run_app_analysis()

        if shutil.which('apt-get'):
            self.logger.info("Guessing APT configuration")
            self.apt_arch = AptRecipeGenerator.get_arch()
            self.apt_sources = AptRecipeGenerator.get_sources()
            self.apt_includes = AptRecipeGenerator.resolve_includes(runtime_analyser.runtime_libs)
            self.apt_excludes = AptRecipeGenerator.resolve_excludes()

        self.files_excludes = [
            'usr/share/man',
            'usr/share/doc/*/README.*',
            'usr/share/doc/*/changelog.*',
            'usr/share/doc/*/NEWS.*',
            'usr/share/doc/*/TODO.*',
        ]

        self.logger.info("No desktop entries found")
        self.appimage_arch = self._guess_appimage_runtime_arch()
        self.runtime_env = {'APPDIR_LIBRARY_PATH': self._define_appdir_library_path(runtime_analyser.runtime_libs)}


    def setup_questions(self):
        # AppDir -> app_info
        print('Basic Information :')
        self.app_info_id = questionary.text('ID [Eg: com.example.app] :', default=self.app_info_id).ask()
        self.app_info_name = questionary.text('Application Name :', default=self.app_info_name).ask()
        self.app_info_icon = questionary.text('Icon :', default=self.app_info_icon).ask()
        self.app_info_version = questionary.text('Version :', default=self.app_info_version).ask()
        self.app_info_exec = questionary.text('Executable path relative to AppDir [usr/bin/app] :',
                                              default=self.app_info_exec).ask()
        self.app_info_exec_args = questionary.text('Arguments [Default: $@] :', default=self.app_info_exec_args).ask()
        self.apt_arch = questionary.select('Architecture :', ['amd64', 'arm64', 'i386', 'armhf'],
                                           default=self.apt_arch).ask()

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
        })

        rendered_yml = appimage_builder_yml_template.render(appimage_builder_yml_ctx)
        logging.info(rendered_yml)

        with open('AppImageBuilder.yml', 'w') as f:
            f.write(rendered_yml)

        self.logger.info("Recipe generation completed.")
        self.logger.info("Please manually fill any blank field left before calling appimage-builder")

    @staticmethod
    def _locate_app_dir():
        for file_name in os.listdir(os.path.curdir):
            if os.path.isdir(file_name) and file_name.lower() == 'appdir':
                return file_name

        raise RecipeGeneratorError('Unable to find an AppDir, this is required to create a recipe.')

    def _setup_app_info(self):
        self.logger.info("Searching desktop entries")
        desktop_files = self._find_desktop_entry_files()
        desktop_file = None
        if len(desktop_files) == 1:
            desktop_file = desktop_files[0]

        if len(desktop_files) > 1:
            desktop_file = questionary.select('Main desktop entry :', desktop_files).ask()

        if desktop_file:
            self.logger.info("Reading desktop entry: %s" % desktop_file)
            parser = DesktopFileParser(desktop_file)
            self.app_info_id = parser.get_id()
            self.app_info_name = parser.get_name()
            self.app_info_icon = parser.get_icon()
            exec = parser.get_exec_path()
            self.app_info_exec = self._resolve_exec_path(exec)
            self.app_info_exec_args = parser.get_exec_args()
            if not self.app_info_exec_args:
                self.app_info_exec_args = '$@'
        else:
            self.logger.info("No desktop entries found")

    def _find_desktop_entry_files(self):
        desktop_entries = []
        for file_name in os.listdir(os.path.abspath(self.app_dir)):
            if file_name.lower().endswith('desktop'):
                desktop_entries.append(file_name)

        for root, dir, files in os.walk(os.path.join(self.app_dir, 'usr', 'share', 'applications')):
            for file_name in files:
                if file_name.lower().endswith('desktop'):
                    desktop_entries.append(os.path.join(root, file_name))

        return desktop_entries

    def _resolve_exec_path(self, exec):
        if '/' in exec and os.path.exists(os.path.join(self.app_dir, exec)):
            return exec

        absolute_app_dir = os.path.abspath(self.app_dir)
        for root, dir, files in os.walk(absolute_app_dir):
            for file in files:
                full_path = os.path.join(root, file)
                if os.access(full_path, os.X_OK):
                    return os.path.relpath(full_path, absolute_app_dir)

        raise RecipeGeneratorError('Unable to find executable: %s' % exec)

    def _guess_appimage_runtime_arch(self):
        file = File()
        signature = file.query(os.path.join(self.app_dir, self.app_info_exec))
        if 'x86-64' in signature:
            return 'x86_64'

        if 'Intel 80386,' in signature:
            return 'i686'

        if 'ARM aarch64,' in signature:
            return 'aarch64'

        if 'ARM,' in signature:
            return 'armhf'

        return None

    @staticmethod
    def _define_appdir_library_path(runtime_libs):
        lib_dirs = set()
        for lib in runtime_libs:
            dirname = os.path.dirname(lib)
            if not dirname.endswith('/dri') and \
                    'qt5/qml' not in dirname and \
                    'qt5/plugins' not in lib:
                lib_dirs.add(dirname)

        runtime_env = ':'.join('$APPDIR%s' % dir for dir in lib_dirs)
        return runtime_env
