#!/usr/bin/python3
import json
import shutil
import subprocess


class QtTool:
    def __init__(self):
        self.qml_source_dir = ""
        self.app_dir = ""
        self.qml_module_dirs = ["/usr/lib"]

        self.qmlimportscanner_bin = shutil.which("qmlimportscanner")
        self.qmake_bin = shutil.which("qmake")

    def query_qt_env(self):
        command = [self.qmake_bin, '-query']
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode != 0:
            raise RuntimeError('Unable to run qmake: "%s"\n%s' %
                               (' '.join(command), result.stderr.decode('utf-8')))

        env = {}
        for line in result.stdout.decode('utf-8').splitlines():
            k, v = line.split(':', 1)
            env[k] = v

        return env

    def qml_scan_imports(self, root_paths=None, import_paths=None):
        command = [self.qmlimportscanner_bin]
        if root_paths:
            command.append('-rootPath')
            command.extend(root_paths)

        if import_paths:
            command.append('-importPath')
            command.extend(import_paths)

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode != 0:
            raise RuntimeError('Unable to run qmlimportscanner: "%s"\n%s' %
                               (' '.join(command), result.stderr.decode('utf-8')))

        output = result.stdout.decode('utf-8')
        return json.loads(output)
