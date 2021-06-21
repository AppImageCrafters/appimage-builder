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
import shutil
from unittest import TestCase, skipIf

from appimagebuilder.context import BundleInfo
from appimagebuilder.modules.generate.recipe_sections.apt_section_generator import (
    AptSectionGenerator,
)
from tests.modules.generate.fake_file_package_resolver import FakeFilePackageResolver
from tests.modules.generate.fake_package_repository_resolver import (
    FakePackageRepositoryResolver,
)


@skipIf(not shutil.which("apt-get"), reason="requires apt-get")
class TestAptSectionGenerator(TestCase):
    def test_generate(self):
        generator = AptSectionGenerator(
            FakeFilePackageResolver({"/lib64/ld-linux-x86-64.so.2": "libc6:amd64"}),
            FakePackageRepositoryResolver(),
        )

        result, missing_files = generator.generate(
            ["/lib64/ld-linux-x86-64.so.2", "/missing/file"],
            BundleInfo(app_dir=pathlib.Path("/tmp")),
        )
        self.assertEqual(["/missing/file"], missing_files)
        self.assertEqual(
            {
                "arch": ["amd64"],
                "allow_unauthenticated": True,
                "sources": [
                    {
                        "sourceline": "deb http://archive.ubuntu.com/ubuntu/ focal main restricted universe multiverse"
                    }
                ],
                "include": ["libc6:amd64"],
            },
            result,
        )
