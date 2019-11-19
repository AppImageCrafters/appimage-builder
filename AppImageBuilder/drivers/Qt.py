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
                        absolute_path = os.path.join(root, file)
                        dependencies.append(QtDependency(self, absolute_path, None, None))

    def lockup_file_dependencies(self, file, app_dir):
        dependencies = []
        if file.endswith('.qml'):
            if file in self.module_dependencies_cache:
                return []

            qml_imports = self._get_qml_file_imports(file)

            for qml_import in qml_imports:
                if 'path' in qml_import:
                    new_dependencies = self._generate_module_dependencies(qml_import, app_dir)

                    for dependency in new_dependencies:
                        dependencies.append(dependency)
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

    def _get_qml_file_imports(self, file):
        import_dirs = [self.qt_env['QT_INSTALL_QML']]
        if 'qml_import_dirs' in self.config:
            import_dirs.extend(self.config['qml_import_dirs'])

        return self.qt.qml_scan_imports([file], import_dirs)

    def _generate_qt_conf(self, app_dir):
        qt_conf_path = self._find_qt_conf()

        qt_conf = configparser.ConfigParser()
        qt_conf.optionxform = str

        if qt_conf_path:
            qt_conf.read(qt_conf_path)

        qt_conf['Paths']['Prefix'] = "../../usr"
        qt_conf['Paths']['Settings'] = "../../etc"

        qt_conf_target_path = self._generate_qt_conf_target_path(app_dir)
        self.logger().info("Writing qt.conf to: %s" % qt_conf_target_path)
        with open(qt_conf_target_path, "w") as f:
            qt_conf.write(f)

    @staticmethod
    def _generate_qt_conf_target_path(app_dir):
        linker_path = tools.Linker.find_binary_path(app_dir.path)
        liker_dir = os.path.dirname(linker_path)
        qt_conf_target_path = os.path.join(liker_dir, "qt.conf")
        return qt_conf_target_path

    @staticmethod
    def _find_qt_conf():
        qt_conf_path = None
        for root, dirs, files in os.walk("/usr"):
            for filename in files:
                if filename == "qt.conf":
                    qt_conf_path = os.path.join(root, filename)

        return qt_conf_path
