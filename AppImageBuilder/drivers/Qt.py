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
import configparser
import os

from AppImageBuilder import tools
from AppImageBuilder.drivers import Base, Dependency


class QtDependency(Dependency):
    qml_module = None

    def __init__(self, driver=None, source=None, target=None, qml_module=None):
        super().__init__(driver, source, target)
        self.qml_module = qml_module

    def __str__(self):
        return '\n'.join([
            '{',
            'driver: %s' % self.driver.id,
            'source: %s' % self.source,
            'target: %s' % self.target,
            'qml_module: %s' % self.qml_module,
        ])


class Qt(Base.Driver):
    id = 'qt'
    qt = None
    qt_env = None

    module_dependencies_cache = set()

    def __init__(self):
        self.qt = tools.QtTool()
        self.qt_env = self.qt.query_qt_env()

    def configure(self, app_dir):
        self._generate_qt_conf(app_dir)

    def list_base_dependencies(self, app_dir):
        dependencies = []
        source_dirs = [app_dir.path]
        if 'qml_source_dirs' in self.config:
            source_dirs.extend(self.config['qml_source_dirs'])

        for source_dir in source_dirs:
            for root, dirs, files in os.walk(source_dir):
                for file in files:
                    if file.endswith('.qml'):
                        absolute_path = os.path.abspath(os.path.join(root, file))
                        dependencies.extend(self.lockup_file_dependencies(absolute_path, app_dir))
        # return dependencies
        return []

    def lockup_file_dependencies(self, file, app_dir):
        dependencies = []
        if file.endswith('.qml'):
            root_dir = os.path.dirname(file)

            if root_dir in self.module_dependencies_cache:
                return []

            self.module_dependencies_cache.add(root_dir)
            self.logger().info("Looking for dependencies of: %s" % root_dir)

            qml_imports = self._get_qml_file_imports(root_dir)

            for qml_import in qml_imports:
                if 'path' in qml_import:
                    new_dependencies = self._generate_module_dependencies(qml_import, app_dir)

                    for dependency in new_dependencies:
                        dependencies.append(dependency)

                        if dependency.source.startswith(root_dir):
                            self.module_dependencies_cache.add(dependency.source)

        return dependencies

    def _generate_module_dependencies(self, qml_import, app_dir):
        if 'path' not in qml_import:
            return []

        path = qml_import['path']
        dependencies = []

        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    absolute_path = os.path.join(root, file)
                    if not app_dir.bundled(absolute_path):
                        dependencies.append(QtDependency(self, absolute_path, None, qml_import))
        else:
            if os.path.exists(path):
                dependencies.append(QtDependency(self, path, None, qml_import))

        return dependencies

    def _get_qml_file_imports(self, dir):
        import_dirs = [self.qt_env['QT_INSTALL_QML']]
        if 'qml_import_dirs' in self.config:
            import_dirs.extend(self.config['qml_import_dirs'])

        return self.qt.qml_scan_imports([dir], import_dirs)

    def _generate_qt_conf(self, app_dir):
        qt_conf_target_path = self._generate_qt_conf_target_path(app_dir)
        linker_dir_path = os.path.dirname(qt_conf_target_path)
        usr_path = os.path.relpath(os.path.join(app_dir.path, 'usr'), linker_dir_path)
        etc_path = os.path.relpath(os.path.join(app_dir.path, 'etc'), linker_dir_path)

        qt_libs_path = None
        qt_lib_execs_path = None
        qt_plugins_path = None
        qt_qml_path = None
        qt_translations_path = None
        qt_data_dir = None

        base_path = os.path.join(app_dir.path, 'usr') + '/'
        for root, dirs, files in os.walk(base_path):
            if 'libQt5Core.so.5' in files and not qt_libs_path:
                qt_libs_path = self._remove_prefix(root, base_path)

            if 'plugins' in dirs and 'qt' in root and not qt_plugins_path:
                qt_plugins_path = self._remove_prefix(os.path.join(root, 'plugins'), base_path)

            if 'libexec' in dirs and 'qt' in root and not qt_lib_execs_path:
                qt_lib_execs_path = self._remove_prefix(os.path.join(root, 'libexec'), base_path)

            if 'qml' in dirs and 'qt' in root and not qt_qml_path:
                qt_qml_path = self._remove_prefix(os.path.join(root, 'qml'), base_path)

            if 'translations' in dirs and 'qt' in root and not qt_translations_path:
                qt_translations_path = self._remove_prefix(os.path.join(root, 'translations'), base_path)

            if 'qt5' in dirs and 'share' in root and not qt_data_dir:
                qt_data_dir = self._remove_prefix(os.path.join(root, 'qt5'), base_path)

        if qt_libs_path:
            qt_conf = [
                '[Paths]\n',
                'Prefix=%s\n' % usr_path,
                'Settings=%s\n' % etc_path,
            ]
            if qt_data_dir:
                qt_conf.append('Data=%s\n' % qt_data_dir)

            if qt_libs_path:
                qt_conf.append('Libraries=%s\n' % qt_libs_path)

            if qt_lib_execs_path:
                qt_conf.append('LibraryExecutables=%s\n' % qt_lib_execs_path)

            if qt_plugins_path:
                qt_conf.append('Plugins=%s\n' % qt_plugins_path)

            if qt_qml_path:
                qt_conf.append('Qml2Imports=%s\n' % qt_qml_path)

            if qt_translations_path:
                qt_conf.append('Translations=%s\n' % qt_translations_path)

            self.logger().info("Writing qt.conf to: %s" % qt_conf_target_path)
            with open(qt_conf_target_path, "w") as f:
                f.writelines(qt_conf)
        else:
            self.logger().info("No Qt5 libs were found. Skipping Qt5 configuration.")

    @staticmethod
    def _remove_prefix(text, prefix):
        if text.startswith(prefix):
            return text[len(prefix):]
        return text  # or whatever

    @staticmethod
    def _generate_qt_conf_target_path(app_dir):
        linker_path = tools.Linker.find_binary_path(app_dir.path)
        liker_dir = os.path.dirname(linker_path)
        qt_conf_target_path = os.path.join(liker_dir, "qt.conf")
        return qt_conf_target_path
