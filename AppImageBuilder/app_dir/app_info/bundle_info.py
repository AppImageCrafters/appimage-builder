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

import yaml
import os

from AppImageBuilder.inspector.inspector import Inspector


class BundleInfo():
    def __init__(self, app_dir, bundlers):
        self.app_dir = app_dir
        self.bundlers = bundlers
        self.data = {}

    def generate(self):
        self._fetch_bundlers_report()
        self._fetch_dependencies()

        path = self.get_file_name()
        with open(path, 'w') as f:
            logging.info('Writing bundle info to: %s' % os.path.relpath(path, self.app_dir))

            app_yaml = yaml.dump(self.data)
            f.write(app_yaml)

    def _fetch_dependencies(self):
        inspector = Inspector(self.app_dir)
        self.data['dependencies'] = list(inspector.get_bundle_needed_libs())

    def _fetch_bundlers_report(self):
        for bundler in self.bundlers:
            report = bundler.get_run_report()
            if report:
                self.data.update(report)

    def get_file_name(self):
        return os.path.join(self.app_dir, '.bundle.yml')
