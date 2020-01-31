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

from AppImageBuilder.commands.repoquery import RepoQuery
from AppImageBuilder.commands.rpm_extract import RpmExtract
from AppImageBuilder.commands.yumdownloader import YumDownloader


class YumError(RuntimeError):
    pass


class Bundler:
    def __init__(self, config):
        self.config = config

        self.yum_downloader = YumDownloader()
        self.repoquery = RepoQuery()
        self.rpm_extract = RpmExtract()



    def deploy_packages(self, app_dir_path):
        download_list = self.repoquery.requires(self.config.include_list, self.config.arch)
        self.yum_downloader.download(download_list, self.config.archives_path)

        self._extract_packages_into_app_dir(app_dir_path)

    def _extract_packages_into_app_dir(self, app_dir_path):
        for file_name in os.listdir(self.config.archives_path):
            package_name = self._get_package_name_from_fime(file_name)
            if self._is_rpm_file(file_name) and not package_name in self.config.exclude_list:
                logging.info("Deploying: %s" % file_name)
                file_path = os.path.join(self.config.archives_path, file_name)
                self.rpm_extract.extract(file_path, app_dir_path)

    def _is_rpm_file(self, file_name):
        return file_name.endswith('.rpm')

    def _get_package_name_from_fime(self, file_name):
        # http://ftp.rpm.org/max-rpm/ch-rpm-file-format.html
        # name-version-release.architecture.rpm
        return file_name[::-1].split('-', 2)[-1][::-1]
