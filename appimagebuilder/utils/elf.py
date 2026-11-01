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
import lief

def has_magic_bytes(path):
    with open(path, "rb") as f:
        bits = f.read(4)
        if bits == b"\x7fELF":
            return True

    return False


def has_soname(path):
    """
    Determine if an elf is a library

    Elf must have a SONAME tag in the dynamic section
    """
    try:
        binary = lief.parse(str(path))
    except Exception:
        return False
 
    if binary is None:
        return False
 
    return any(
        entry.tag == lief.ELF.DynamicEntry.TAG.SONAME
        for entry in binary.dynamic_entries
    )


def has_interp_section(path):
    """
    Determine if an elf is executable

    Linux executables often lack a `_start_` if they've been stripped. The kernel usually starts from a memory address instead. What we care about is patching the dynamic linker reference, so let's look for that instead.

    https://unix.stackexchange.com/questions/454726/where-is-start-symbol-in-cat-executable
    """
    try:
        binary = lief.parse(str(path))
    except Exception:
        return False
    if binary is None:
        return False
    return binary.has(lief.ELF.Segment.TYPE.INTERP) and not has_soname(path)




def get_arch(path):
    """
    Read the target instructions set architecture and maps it to a name known by appimage-builder

    https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header
    """
    known_architectures = {
        b"\xB7": "aarch64",
        b"\x28": "gnueabihf",
        b"\x03": "i386",
        b"\x3E": "x86_64",
    }

    with open(path, "rb") as f:
        f.seek(18)
        e_machine = f.read(1)
        if e_machine in known_architectures:
            return known_architectures[e_machine]
        else:
            raise RuntimeError(
                "Unknown instructions set architecture `%s` on: %s"
                % (e_machine.hex(), path)
            )
