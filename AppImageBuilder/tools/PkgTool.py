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
import re
import shutil
import subprocess
import logging

from AppImageBuilder.FileUtils import make_link_relative


class PkgTool:
    target_arch = None

    def __init__(self):
        self.logger = logging.getLogger("PkgTool")
        self.target_arch = self.get_deb_host_arch()

    def find_package_dependencies(self, package_name):
        result = subprocess.run(["apt-cache", "depends", package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        errors = result.stderr.decode('utf-8')

        depends = []
        if result.returncode != 0:
            self.logger.warning("Unable to find %s dependencies: %s" % (package_name, errors))
        else:
            for line in output.splitlines():
                depends_search = re.search(r'Depends: (?P<pkg_name>(\w|\.|-|_|\d)+)', line, re.IGNORECASE)
                if depends_search:
                    depends.append(depends_search.group('pkg_name'))

        return depends

    def find_owner_packages(self, paths):
        packages = set()
        command = ["dpkg-query", "-S"]
        if isinstance(paths, list):
            command.extend(paths)
        else:
            command.append(paths)

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        errors = result.stderr.decode('utf-8')

        for line in errors.splitlines():
            if line.startswith("dpkg-query: no path found matching pattern"):
                self.logger.error(line)

        for line in output.splitlines():
            line_packages = self._parse_package_names_from_dpkg_query_output(line)

            for package in line_packages:
                if ':' not in package:
                    # not an arch specific package
                    packages.add(package)
                else:
                    # arch specific package
                    if self.target_arch in package:
                        # only use packages matching the target arch
                        packages.add(package)

        return packages

    def _parse_package_names_from_dpkg_query_output(self, line):
        regex = r'((?P<package>(\w|-|_|\.|\+)+(:((\w|-|_)+))?))( |:|,)'
        matches = re.finditer(regex, line, re.MULTILINE)

        packages = set()
        for matchNum, match in enumerate(matches, start=1):

            self.logger.debug(
                "Match {matchNum} was found at {start}-{end}: {match}".format(matchNum=matchNum, start=match.start(),
                                                                              end=match.end(), match=match.group()))

            group_dict = match.groupdict()
            if 'package' in group_dict:
                packages.add(group_dict['package'])

        return packages

    def list_package_files(self, package):
        files = []

        result = subprocess.run(["dpkg-query", "-L", package], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode('utf-8')

        if result.returncode != 0:
            return files

        for line in output.splitlines():
            if os.path.isfile(line):
                files.append(line)

        return files

    def deploy_pkgs(self, pkgs, app_dir_path):
        extracted_files = {}
        for pkg in pkgs:
            self.logger.info("Deploying package: %s" % pkg)
            files = self.list_package_files(pkg)

            for file in files:
                target_file = app_dir_path + file

                os.makedirs(os.path.dirname(target_file), exist_ok=True)

                try:
                    shutil.copy2(file, target_file)
                    self.logger.info(" + %s", file)
                except RuntimeError as error:
                    self.logger.warning(" * %s (%s)" % (file, error))

                extracted_files[file] = pkg
                if os.path.islink(target_file):
                    self._make_links_relative_to_app_dir(app_dir_path, target_file)

        return extracted_files

    @staticmethod
    def _make_links_relative_to_app_dir(app_dir, target_file):
        link_target = os.readlink(target_file)
        if link_target.startswith("/"):
            logging.info("Making link %s relative to %s", link_target, app_dir)
            make_link_relative(app_dir, target_file, link_target)

    def _extract_pkg_to(self, pkg_file, target_dir):
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
        target_dir = os.path.abspath(target_dir)

        command = ["dpkg-deb", "-X", pkg_file, target_dir]
        self.logger.debug(command)
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=target_dir)
        self.logger.info("Deployed files:\n%s" % result.stdout.decode('utf-8'))

        if result.returncode != 0:
            self.logger.error("Package extraction failed. Error: " + result.stderr.decode('utf-8'))
            return []

        return result.stdout.decode('utf-8').splitlines()

    def _extract_pkgs_to(self, temp_dir, appdir):
        extraction_map = {}
        for root, dirs, files in os.walk(temp_dir):
            for filename in files:
                if filename.endswith(".deb"):
                    self.logger.info("Extracting: %s" % filename)
                    extracted_files = self._extract_pkg_to(os.path.join(root, filename), appdir)

                    for extracted_file in extracted_files:
                        extraction_map[extracted_file] = os.path.basename(filename)

        return extraction_map

    @staticmethod
    def get_deb_host_arch():
        result = subprocess.run(["dpkg-architecture", "-q", 'DEB_HOST_ARCH'], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        if result.returncode == 0:
            return result.stdout.decode('utf-8').strip()
        else:
            return None

    def remove_pkgs(self, pkgs, app_dir_path):
        for pkg in pkgs:
            files = self.list_package_files(pkg)
            self.logger.info("Removing package: %s", pkg)
            for file in files:
                full_path = app_dir_path + file

                if os.path.exists(full_path):
                    os.remove(full_path)
                    self.logger.info(" - %s", full_path)
                else:
                    self.logger.info(" * %s (not deployed)", full_path)

            self.logger.info("Package removed: %s", pkg)
