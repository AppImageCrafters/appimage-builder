#   Copyright  2020 Alexis Lopez Zubieta
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the "Software"),
#   to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#   sell copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
import fnmatch
import re
import subprocess
import urllib

from .errors import PackageDeployError


def filter_packages_cache(patterns):
    output = subprocess.run(
        "apt-cache pkgnames", stdout=subprocess.PIPE, shell=True
    )
    if output.returncode:
        raise PackageDeployError(
            '"%s" execution failed with code %s' % (output.args, output.returncode)
        )
    packages = output.stdout.decode("utf-8").splitlines()

    filtered_packages = []
    for pattern in patterns:
        filtered_packages.extend(fnmatch.filter(packages, pattern))

    return filtered_packages


def parse_deb_info(stdout):
    """Read the first package information from the dpkg-deb --info output"""
    package = {}

    # read package name
    search = re.match("Package: (.+)\n", stdout)
    package["name"] = search.group(1)

    search = re.search("Architecture: (.*)", stdout, flags=re.MULTILINE)
    package["architecture"] = search.group(1)

    search = re.search("Version: (.*)", stdout, flags=re.MULTILINE)
    package["version"] = search.group(1)

    search = re.search("Pre-Depends: (.*)", stdout, flags=re.MULTILINE)
    if search:
        pkg_list = search.group(1).split(",")
        pkg_list = [pkg.strip() for pkg in pkg_list]
        pkg_list = [pkg.split(" ")[0] for pkg in pkg_list]
        package["pre-depends"] = pkg_list
    else:
        package["pre-depends"] = []

    search = re.search("Depends: (.*)", stdout, flags=re.MULTILINE)
    if search:
        pkg_list = search.group(1).split(",")
        pkg_list = [pkg.strip() for pkg in pkg_list]
        pkg_list = [pkg.split(" ")[0] for pkg in pkg_list]
        package["depends"] = pkg_list
    else:
        package["depends"] = []

    return package


def resolve_packages_from_simulated_install(packages) -> (str, str, str):
    output = run_apt_get_simulate_install(packages)
    if output.returncode:
        raise PackageDeployError(
            '"%s" execution failed with code %s' % (output.args, output.returncode)
        )

    results = extract_packages_from_apt_get_install_output(output.stdout.decode("utf-8"))
    return results


def extract_packages_from_apt_get_install_output(output_str):
    # extract packages name, version and architecture
    results = re.findall(
        "Inst\s+(?P<pkg_name>[\w|\d|\-|\.]+)\s+\((?P<pkg_version>\S+)\s.*\[(?P<pkg_arch>.*)\]\)",
        output_str,
    )
    return results


def package_tuples_to_file_names(package_tuples):
    package_files = ["%s_%s_%s.deb" % pkg for pkg in package_tuples]

    # apt encodes invalid chars to follow the deb file naming convention
    package_files = [
        urllib.parse.quote(pkg, safe="+").lower() for pkg in package_files
    ]

    return package_files


def run_apt_get_simulate_install(packages):
    output = subprocess.run(
        "apt-get install -y --simulate %s" % (" ".join(packages)),
        stdout=subprocess.PIPE,
        shell=True,
    )
    if output.returncode:
        raise PackageDeployError(
            '"%s" execution failed with code %s' % (output.args, output.returncode)
        )
    return output


def run_apt_get_update():
    output = subprocess.run("apt-get update", shell=True)
    if output.returncode:
        raise PackageDeployError(
            '"%s" execution failed with code %s' % (output.args, output.returncode)
        )


def run_dpkg_deb_extract(package_path, target):
    output = subprocess.run(
        "dpkg-deb -x %s %s" % (package_path, target), shell=True
    )
    if output.returncode:
        raise PackageDeployError(
            '"%s" execution failed with code %s' % (output.args, output.returncode)
        )


def run_apt_get_install_download_only(packages):
    output = subprocess.run(
        "apt-get install -y --download-only %s" % (" ".join(packages)),
        shell=True,
    )
    if output.returncode:
        raise PackageDeployError(
            '"%s" execution failed with code %s' % (output.args, output.returncode)
        )
