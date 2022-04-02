import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

from appimagebuilder.modules.setup.environment import Environment
from appimagebuilder.modules.setup.libraries_patcher import LibrariesPatcher
from appimagebuilder.utils.patchelf import PatchElf


class TestLibrariesPatcher(unittest.TestCase):
    def setUp(self) -> None:
        self.test_appdir = tempfile.TemporaryDirectory(prefix="AppDir-")
        self.test_appdir_path = pathlib.Path(self.test_appdir.name)
        self.patcher = LibrariesPatcher(self.test_appdir_path, Environment())
        self._copy_sh()

    def _copy_sh(self):
        bash_path = shutil.which("bash")
        self.test_bin_path = pathlib.Path(self.test_appdir.name + bash_path)
        self.test_bin_path.parent.mkdir(exist_ok=True, parents=True)
        shutil.copy(bash_path, self.test_bin_path)

        process = subprocess.run(["ldd", bash_path], capture_output=True)
        output = process.stdout.decode()
        match_lib_paths_from_ldd_output = re.compile(r"=> (/.*) \(.*")
        lib_paths = match_lib_paths_from_ldd_output.findall(output)
        for path in lib_paths:
            path = pathlib.Path(path)
            if path.match("libc.*"):
                target_path = pathlib.Path(
                    self.test_appdir.name + "/runtime/compat" + str(path)
                )
                self.libc_dir_prefix = path.parent

                # create fake libapprun_hooks
                fake_libapprun_hooks = pathlib.Path(
                    self.test_appdir.name + "/lib/libapprun_hooks.so"
                )
                fake_libapprun_hooks.parent.mkdir(exist_ok=True, parents=True)
                shutil.copy(path, fake_libapprun_hooks)
            else:
                target_path = pathlib.Path(self.test_appdir.name + str(path))

            target_path.parent.mkdir(exist_ok=True, parents=True)
            shutil.copy(path, target_path)

    def tearDown(self) -> None:
        self.test_appdir.cleanup()

    def test_patch_rpaths(self):
        self.patcher.patch_rpaths()

        patchelf = PatchElf()
        rpath = patchelf.get_rpath(self.test_bin_path)

        bin_depth = len(self.test_bin_path.relative_to(self.test_appdir_path).parts) - 1
        # assert libs paths were included
        self.assertIn("$ORIGIN" + "/.." * bin_depth + str(self.libc_dir_prefix), rpath)

        # assert libapprun_hooks.so path was included
        self.assertIn("$ORIGIN" + "/.." * bin_depth + "/lib", rpath)

        # assert libc path was included relative to the current working dir
        self.assertIn(str(self.libc_dir_prefix)[1:], rpath)


if __name__ == "__main__":
    unittest.main()
