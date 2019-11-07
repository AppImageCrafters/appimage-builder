#!/usr/bin/env python3
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
import argparse
import yaml
import json
import pprint
import logging
import platform
from shutil import copyfile
from AppImageCraft.AppDir import AppDir
from AppImageCraft.TestsTool import TestsTool
from AppImageCraft.AppImageTool import AppImageTool
from AppImageCraft.DesktopEntryBuilder import DesktopEntryBuilder
from AppImageCraft.ShellTool import ShellTool


def __main__():
    parser = argparse.ArgumentParser(description='AppImage crafting tool')
    parser.add_argument('--recipe', dest='recipe', default=os.path.join(os.getcwd(), "AppImageCraft.yml"),
                        help='recipe file path (default: $PWD/AppImageCraft.yml)')
    parser.add_argument('--log', dest='loglevel', default="INFO",
                        help='logging level (default: INFO)')
    parser.add_argument('--skip-script', dest='skip_script', action="store_true",
                        help='Skip running script section')
    parser.add_argument('--skip-install', dest='skip_install', action="store_true",
                        help='Skip dependencies installation')
    parser.add_argument('--skip-tests', dest='skip_tests', action="store_true",
                        help='Skip running docker tests')
    parser.add_argument('--skip-appimage', dest='skip_appimage', action="store_true",
                        help='Skip AppImage generation')

    args = parser.parse_args()
    _configure_logger(args)

    recipe = _load_recipe_file(args.recipe)
    if not recipe:
        return 1

    logging.debug("Recipe: \n%s\n" % pprint.pformat(recipe))

    if not args.skip_script:
        _execute_script(recipe)

    app_dir = AppDir()
    _execute_app_dir(recipe, app_dir, args.skip_install, args.skip_tests)

    if not args.skip_appimage:
        _execute_appimage(app_dir, recipe)


def _execute_script(recipe):
    script_recipe = _check_optional_recipe_entry("script", recipe, list())
    if not isinstance(script_recipe, list):
        logging.error("Malformed recipe. 'script' entry must be a list")
    shell_tool = ShellTool()
    shell_tool.execute(script_recipe)


def _execute_appimage(app_dir, recipe):
    appimage_tool = AppImageTool()
    app_recipe = _check_recipe_entry("App", recipe)
    app_name = _check_recipe_entry("name", app_recipe)
    app_version = _check_recipe_entry("version", app_recipe)
    output_file = os.path.join(os.getcwd(), "%s-%s-%s.AppImage" % (app_name, app_version, platform.machine()))
    appimage_tool.bundle(app_dir.path, output_file)


def _generate_desktop_entry(app_dir, recipe):
    logging.info("Generating desktop entry.")
    app_recipe = _check_recipe_entry("App", recipe)

    builder = DesktopEntryBuilder()

    builder.app_id = _check_recipe_entry("id", app_recipe)
    builder.app_name = _check_recipe_entry("name", app_recipe)
    builder.app_icon = _check_recipe_entry("icon", app_recipe)
    builder.app_version = _check_recipe_entry("version", app_recipe)
    builder.app_categories = _check_optional_recipe_entry("categories", app_recipe, ["Utility"])
    builder.app_summary = _check_optional_recipe_entry("summary", app_recipe, "")

    desktop_entry_path = os.path.join(app_dir.path, builder.get_file_name())
    builder.generate(desktop_entry_path)


def _check_recipe_entry(entry, recipe):
    if entry in recipe:
        return recipe[entry]

    logging.error("Missing '%s' entry in recipe" % entry)


def _check_optional_recipe_entry(entry, recipe, fallback):
    if entry in recipe:
        return recipe[entry]

    return fallback


def _copy_icon_from_theme(app_dir, recipe):
    app_recipe = _check_recipe_entry("App", recipe)
    app_icon = _check_recipe_entry("icon", app_recipe)
    logging.info("Importing icon '%s' from theme" % app_icon)

    icon_path = None
    for root, dirs, files in os.walk("/usr/share/icons"):
        for filename in files:
            if app_icon in filename:
                icon_path = os.path.join(root, filename)

    target_icon_path = os.path.join(os.path.abspath(app_dir.path), os.path.basename(icon_path))
    logging.info("Coping: '%s' to '%s'" % (icon_path, target_icon_path))
    copyfile(icon_path, target_icon_path)


def _execute_app_dir(recipe, app_dir, skip_install=False, skip_tests=False):
    app_recipe = _check_recipe_entry('App', recipe)
    app_dir.app_runnable = _check_recipe_entry('exec', app_recipe)

    app_dir_recipe = _check_recipe_entry('AppDir', recipe)
    app_dir.path = os.path.abspath(_check_recipe_entry('path', app_dir_recipe))

    if not skip_install:
        install_requirements(app_dir_recipe, app_dir)

        with open(os.path.join(app_dir.path, "deployed_files.json"), "w") as f:
            f.write(json.dumps(app_dir.deploy_registry, indent=2, sort_keys=True))

        with open(os.path.join(app_dir.path, "deployed_libs.json"), "w") as f:
            f.write(json.dumps(app_dir.libs_registry, indent=2, sort_keys=True))

    app_dir.generate_app_run()

    addons = _check_optional_recipe_entry("addons", app_dir_recipe, None)
    if addons:
        if 'generate-desktop-entry' in addons:
            _generate_desktop_entry(app_dir, recipe)

        if 'copy-icon-from-theme' in addons:
            _copy_icon_from_theme(app_dir, recipe)

    if not skip_tests:
        tests_recipe = _check_recipe_entry('test', app_dir_recipe)
        run_tests(app_dir, tests_recipe)


def _load_recipe_file(recipe_path):
    try:
        with open(recipe_path) as f:
            return yaml.load(f, Loader=yaml.FullLoader)
    except:
        logging.error("Unable to read recipe file: %s" % recipe_path)


def install_requirements(recipe, app_dir):
    apt_include = []
    apt_exclude = []
    if 'apt' in recipe:
        (apt_include, apt_exclude) = _read_apt_instructions(app_dir, recipe)

    app_dir.install(apt_include, apt_exclude)


def _read_apt_instructions(app_dir, recipe):
    apt_include = []
    apt_exclude = []
    if 'include' in recipe['apt']:
        if not isinstance(recipe['apt']['include'], list):
            logging.error("Malformed recipe. 'apt' > 'include' entry must be a list")

        apt_include = recipe['apt']['include']
    if 'exclude' in recipe['apt']:
        if not isinstance(recipe['apt']['exclude'], list):
            logging.error("Malformed recipe. 'apt' > 'exclude' entry must be a list")

        apt_exclude = recipe['apt']['exclude']

    return (apt_include, apt_exclude)


def _configure_logger(args):
    numeric_level = getattr(logging, args.loglevel.upper())
    if not isinstance(numeric_level, int):
        logging.error('Invalid log level: %s' % args.loglevel)
    logging.basicConfig(level=numeric_level)


def run_tests(app_dir, test_scenarios):
    if not isinstance(test_scenarios, dict):
        logging.error("Malformed recipe. 'test' entry must be a dict")

    tests_tool = TestsTool(app_dir, test_scenarios)
    tests_tool.run_tests()


if __name__ == '__main__':
    # execute only if run as the entry point into the program
    __main__()
