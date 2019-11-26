import os
import shutil
import tempfile
import unittest

from AppImageBuilder.tools.QtTool import QtTool


class QmlImportScannerToolTestCase(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.qml_module_dir_file_path = os.path.join(self.test_dir, "qml_module", 'qmldir')

        os.makedirs(os.path.dirname(self.qml_module_dir_file_path))

        with open(self.qml_module_dir_file_path, 'w') as qmldir_file:
            qmldir_file.write('\n'.join(['module qml_module\n',
                                         'plugin qml_module_plugin']))

        self.qml_file_path = os.path.join(self.test_dir, "qml_project", 'file.qml')

        os.makedirs(os.path.dirname(self.qml_file_path))

        with open(self.qml_file_path, 'w') as qml_file:
            qml_file.writelines('\n'.join(['import QtQuick 2.0',
                                           'import qml_module 1.0',
                                           'Item {', '}']))

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_query_qt_env(self):
        qt = QtTool()
        env = qt.query_qt_env()
        self.assertEqual(env['QT_INSTALL_QML'], '/usr/lib/x86_64-linux-gnu/qt5/qml')

    def test_qml_scan_imports(self):
        qt = QtTool()
        qml_project_root = [os.path.join(self.test_dir, "qml_project")]
        import_dirs = [self.test_dir]

        imports = qt.qml_scan_imports(qml_project_root, import_dirs)
        expected = [
            {'name': 'QtQuick', 'type': 'module', 'version': '2.0'},
            {'name': 'qml_module', 'path': os.path.dirname(self.qml_module_dir_file_path),
             'plugin': 'qml_module_plugin',
             'relativePath': 'qml_module', 'type': 'module', 'version': '1.0'}
        ]
        self.assertEqual(expected, imports)


if __name__ == '__main__':
    unittest.main()
