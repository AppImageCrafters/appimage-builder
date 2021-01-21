from unittest import TestCase

from appimagebuilder.common.file_test import read_elf_arch


class Test(TestCase):
    def test_read_elf_arch(self):
        self.assertEqual("i386", read_elf_arch("/lib/ld-linux.so.2"))
        self.assertEqual("x86_64", read_elf_arch("/lib64/ld-linux-x86-64.so.2"))

        # self.assertEqual("i386", read_elf_arch("/tmp/AppRun-Release-i386"))
        # self.assertEqual("x86_64", read_elf_arch("/tmp/AppRun-Release-x86_64"))
        # self.assertEqual("aarch64", read_elf_arch("/tmp/AppRun-Release-aarch64"))
        # self.assertEqual("gnueabihf", read_elf_arch("/tmp/AppRun-Release-gnueabihf"))
