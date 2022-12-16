import shutil
from unittest import TestCase, skipIf

from appimagebuilder.modules.deploy.apt.package import Package


@skipIf(not shutil.which("apt-get"), reason="requires apt-get")
class TestPackage(TestCase):

    def test_compare_versions(self):
        package_a = Package("test", "1.19.7ubuntu3", "aarch64")
        package_b = Package("test", "1.19.8", "aarch64")

        self.assertGreater(package_b, package_a)

        package_a = Package("test", "1.19.7", "aarch64")
        package_b = Package("test", "1.19.8", "aarch64")

        self.assertGreater(package_b, package_a)

        package_a = Package("test", "1.19.7ubuntu3", "aarch64")
        package_b = Package("test", "1.19.7ubuntu3", "aarch64")

        self.assertEqual(package_b, package_a)

        package_a = Package("test", "0", "aarch64")
        package_b = Package("test", "10", "aarch64")

        self.assertGreater(package_b, package_a)