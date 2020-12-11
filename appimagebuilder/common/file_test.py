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
import subprocess


def is_elf(path):
    with open(path, "rb") as f:
        bits = f.read(4)
        if bits == b"\x7fELF":
            return True

    return False


def is_elf_executable(path):
    """
    Determine if an elf is executable

    The `__libc_start_main` symbol should be present in every runnable elf file.
    https://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/baselib---libc-start-main-.html
     """
    has_main_method = False
    _proc = subprocess.run("readelf -s %s" % path, stdout=subprocess.PIPE, shell=True)
    if _proc.returncode == 0:
        output = _proc.stdout.decode("utf-8")
        has_main_method = '__libc_start_main' in output
    return has_main_method
