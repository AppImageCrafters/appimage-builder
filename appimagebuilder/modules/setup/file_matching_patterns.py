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

"""
Manually curated list of file matching patterns used to identify certain parts of the AppDir.

Groups describe matching that are binary dependent between them and must be used together at runtime. Excluding them
from the list will result in a failure.
"""

"glibc related binaries"
glibc = [
    "**/audit/*",
    "**/doc/gcc-10-base/*",
    "**/doc/libc6/*",
    "**/doc/libcrypt1/*",
    "**/doc/libgcc-s1/*",
    "**/doc/zlib1g/*",
    "**/gconv/*",
    "**/ld-*.so",
    "**/ld-linux-x86-64.so*",
    "**/ld-linux-x86-64.so*",
    "**/ld-linux-x86-64.so.2",
    "**/ld-linux.so.2",
    "**/libBrokenLocale-*.so",
    "**/libBrokenLocale.so*",
    "**/libSegFault.so",
    "**/libanl-*.so",
    "**/libanl.so*",
    "**/libc-*.so",
    "**/libc.so*",
    "**/libcrypt.so*",
    "**/libcrypt.so*",
    "**/libdl-*.so",
    "**/libdl.so*",
    "**/libgcc_s.so*",
    "**/libm-*.so",
    "**/libm.so*",
    "**/libmemusage.so*",
    "**/libmvec-*.so",
    "**/libmvec.so*",
    "**/libnsl-*.so",
    "**/libnsl.so*",
    "**/libnss_compat-*.so",
    "**/libnss_compat.so*",
    "**/libnss_dns-*.so",
    "**/libnss_dns.so*",
    "**/libnss_files-*.so",
    "**/libnss_files.so*",
    "**/libnss_hesiod-*.so",
    "**/libnss_hesiod.so*",
    "**/libnss_nis-*.so",
    "**/libnss_nis.so*",
    "**/libnss_nisplus-*.so",
    "**/libnss_nisplus.so*",
    "**/libpcprofile.so",
    "**/libpthread-*.so",
    "**/libpthread.so*",
    "**/libresolv-*.so",
    "**/libresolv.so*",
    "**/librt-*.so",
    "**/librt.so*",
    "**/libstdcxx/*",
    "**/libthread_db-*.so",
    "**/libthread_db.so*",
    "**/libutil-*.so",
    "**/libutil.so*",
    "**/libz.so*",
    "**/libz.so*",
    "etc/ld.so.conf.d/*",
]

"glibstdc++ related binaries"
glibstdcpp = [
    "**/doc/libstdc++6/*",
    "**/libstdc++.so*",
    "**/libstdc++stdc++.so*",
]

"glibc and glibstc++ related binaries (used for compatibility with AppRun v2)"
glibc_with_glibstdcpp = glibc + glibstdcpp
