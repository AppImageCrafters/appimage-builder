import os.path
from unittest import TestCase, skipIf

from appimagebuilder.utils.elf import get_arch


class Test(TestCase):
    @skipIf(not os.path.isfile("/lib/ld-linux.so.2"), "/lib/ld-linux.so.2 is required")
    def test_read_elf_arch_i386(self):
        self.assertEqual("i386", get_arch("/lib/ld-linux.so.2"))

    @skipIf(
        not os.path.isfile("/lib64/ld-linux-x86-64.so.2"),
        "/lib64/ld-linux-x86-64.so.2 is required",
    )
    def test_read_elf_arch_x86_64(self):
        self.assertEqual("x86_64", get_arch("/lib64/ld-linux-x86-64.so.2"))
