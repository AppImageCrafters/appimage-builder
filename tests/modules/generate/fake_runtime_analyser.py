#  Copyright  2021 Alexis Lopez Zubieta
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
import pathlib

from appimagebuilder.modules.analisys.app_runtime_analyser import AppRuntimeAnalyser


class FakeAppRuntimeAnalyser(AppRuntimeAnalyser):
    def __init__(self, expected_result):
        self.expected_result = expected_result

    def run_app_analysis(self, app_dir: pathlib.Path, exec: str, exec_args: str):
        return self.expected_result
