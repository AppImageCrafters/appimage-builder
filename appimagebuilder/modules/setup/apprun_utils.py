#  Copyright  2022 Alexis Lopez Zubieta
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
import shlex

import libconf
import lief
import urllib3


def identify_module_library_paths(files):
    """Identifies library paths for a module"""

    library_paths = set()
    for file in files:
        file_dir = file.parent.__str__()

        # only parse file if the directory is not already in the library paths
        if file_dir not in library_paths:
            binary = lief.parse(file.__str__())
            if is_binary_a_shared_library(binary):
                library_paths.add(file_dir)

    return library_paths


def is_binary_a_shared_library(binary):
    """Checks if a binary is a shared library"""

    # read soname from ELF header
    if binary:
        soname = binary.get(lief.ELF.DYNAMIC_TAGS.SONAME)
        return soname is not None

    return False


def download_file_by_chunks_using_urlib3(apprun_url, target_path):
    """Downloads a file by chunks using urllib3"""

    http = urllib3.PoolManager()
    r = http.request("GET", apprun_url)
    with open(target_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)


def write_config_file(config, path):
    """Writes a config file"""
    with open(path, "w") as f:
        config_data = libconf.dumps(config)
        f.write(config_data)


def read_shebang(path):
    with open(path, "rb") as f:
        buf = f.read(128)

        if len(buf) < 2 or buf[0] != ord("#") or buf[1] != ord("!"):
            return None

        end_idx = buf.find(b"\n")
        if end_idx == -1:
            end_idx = len(buf)

        buf = buf[2:end_idx].decode()
        buf = buf.strip()

        parts = buf.split(" ")
        parts = [part.strip() for part in parts if part]
        return parts


def remove_left_slashes_on_shebang(chunk):
    """Removes left slashes on shebang"""

    for i in range(2, len(chunk)):
        # if the character is not a slash, we are done
        if chunk[i] != ord("/") and chunk[i] != ord(" "):
            return chunk[:2] + b" " * (i - 2) + chunk[i:]

    return chunk


def replace_app_dir_in_path(appdir, path):
    """Replaces the app dir in a path"""

    path_str = str(path)
    appdir_str = str(appdir)
    return path_str.replace(appdir_str, "$APPDIR")
