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

from AppImageBuilder.tools.PkgTool import PkgTool as Dpkg
from AppImageBuilder.tools.LinkerTool import LinkerTool as Linker
from AppImageBuilder.tools.ShellTool import ShellTool as Shell
from AppImageBuilder.tools.AppImageTool import AppImageTool as AppImage
from AppImageBuilder.tools.QtTool import QtTool
from AppImageBuilder.tools.TestsTool import TestsTool