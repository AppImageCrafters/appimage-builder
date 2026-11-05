#!/usr/bin/env bash
# Building embedded images is broken under stock Ubuntu 26,
# because the rust coreutils version is severely broken, and doesnt react to bugreports.
# UEFI files get corrupted e.g.
# https://computingforgeeks.com/ubuntu-2604-rust-coreutils-guide/ is quite ok, but not fully.
#
# Replace Ubuntu 26's uutils selector with GNU coreutils while keeping
# build-essential dependent on the implementation-neutral coreutils package.
# Tested in a fresh Ubuntu-26.04 container

set -Eeuo pipefail
export DEBIAN_FRONTEND=${DEBIAN_FRONTEND:-noninteractive}

usage() {
    cat <<'EOF'
Usage: sudo ./replace-uutils-with-gnu-coreutils-ubuntu26.sh [options]

Options:
  --build-only       Build the corrected build-essential package; do not install it.
  --output-dir DIR   Keep the corrected package in DIR (default: /var/tmp).
  -h, --help         Show this help.
EOF
}

build_only=false
output_dir=/var/tmp

while (($#)); do
    case "$1" in
        --build-only)
            build_only=true
            shift
            ;;
        --output-dir)
            (($# >= 2)) || { printf 'error: --output-dir requires a directory\n' >&2; exit 2; }
            output_dir=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'error: unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ! -r /etc/os-release ]]; then
    printf 'error: /etc/os-release is unavailable\n' >&2
    exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 26.* ]]; then
    printf 'error: this recipe is only for Ubuntu 26.x; found %s %s\n' \
        "${ID:-unknown}" "${VERSION_ID:-unknown}" >&2
    exit 1
fi

if ! $build_only && ((EUID != 0)); then
    printf 'error: run the installation with sudo (or use --build-only)\n' >&2
    exit 1
fi

for command in apt-cache apt-get awk dpkg dpkg-deb dpkg-query mktemp; do
    command -v "$command" >/dev/null || {
        printf 'error: required command not found: %s\n' "$command" >&2
        exit 1
    }
done

is_installed() {
    [[ $(dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null || true) == ii* ]]
}

installed_build_essential_depends=$(dpkg-query -W -f='${Depends}' build-essential 2>/dev/null || true)
if ! $build_only \
    && [[ $installed_build_essential_depends == *coreutils* ]] \
    && [[ $installed_build_essential_depends != *coreutils-from-uutils* ]] \
    && is_installed coreutils-from-gnu; then
    printf 'Already configured: build-essential uses coreutils and coreutils-from-gnu is installed.\n'
    exit 0
fi

if ! $build_only; then
    apt-get update
fi

archive_version=$(apt-cache madison build-essential | awk 'NR == 1 { print $3 }')
if [[ -z $archive_version ]]; then
    printf 'error: no archive version of build-essential is available\n' >&2
    exit 1
fi
local_version="${archive_version}+coreutilsgnu1"
architecture=$(dpkg --print-architecture)

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/build-essential-coreutils-gnu.XXXXXXXX")
cleanup() {
    rm -rf "$work_dir"
}
trap cleanup EXIT
chmod 0755 "$work_dir"
download_dir=$work_dir/download
mkdir "$download_dir"
if ((EUID == 0)) && id -u _apt >/dev/null 2>&1; then
    chown _apt:root "$download_dir"
fi

(
    cd "$download_dir"
    apt-get download "build-essential=$archive_version"
)

shopt -s nullglob
downloaded_packages=("$download_dir"/build-essential_*.deb)
shopt -u nullglob
if ((${#downloaded_packages[@]} != 1)); then
    printf 'error: expected one downloaded build-essential package, found %d\n' \
        "${#downloaded_packages[@]}" >&2
    exit 1
fi

package_root=$work_dir/package
dpkg-deb --raw-extract "${downloaded_packages[0]}" "$package_root"
control_file=$package_root/DEBIAN/control
original_depends=$(dpkg-deb -f "${downloaded_packages[0]}" Depends)
if [[ $original_depends != *coreutils-from-uutils* ]]; then
    printf 'error: archive build-essential no longer depends on coreutils-from-uutils; refusing to rewrite unexpected metadata\n' >&2
    exit 1
fi

awk -v version="$local_version" '
    /^Version: / {
        print "Version: " version
        next
    }
    /^Maintainer: / {
        print "Maintainer: Local Administrator <root@localhost>"
        next
    }
    /^Depends: / {
        if (sub(/coreutils-from-uutils([[:space:]]*\([^)]*\))?/, "coreutils") != 1) {
            exit 42
        }
        print
        next
    }
    { print }
' "$control_file" >"$control_file.new" || {
    status=$?
    printf 'error: failed to rewrite build-essential control metadata (status %d)\n' "$status" >&2
    exit "$status"
}
mv "$control_file.new" "$control_file"

mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd -P)
version_for_filename=${local_version//:/%3a}
output_package=$output_dir/build-essential_${version_for_filename}_${architecture}.deb
dpkg-deb --root-owner-group --build "$package_root" "$output_package"

rebuilt_depends=$(dpkg-deb -f "$output_package" Depends)
rebuilt_version=$(dpkg-deb -f "$output_package" Version)
if [[ $rebuilt_version != "$local_version" \
    || $rebuilt_depends == *coreutils-from-uutils* \
    || $rebuilt_depends != *coreutils* ]]; then
    printf 'error: rebuilt package failed metadata validation\n' >&2
    exit 1
fi

printf 'Built corrected package: %s\n' "$output_package"
printf 'Depends: %s\n' "$rebuilt_depends"

if $build_only; then
    exit 0
fi

# Unpack first so this also works on minimal images where build-essential's
# compiler dependencies are not installed yet. Resolve those dependencies while
# uutils still satisfies coreutils' selector pre-dependency.
dpkg --unpack "$output_package"
apt-get --fix-broken install -y

# These selector packages conflict through their shared coreutils-from virtual
# package. Name the removal explicitly so APT can solve the handoff. Ubuntu marks
# the uutils selector Protected, so noninteractive replacement requires
# --allow-remove-essential; coreutils-from-gnu is installed in the same APT
# transaction and performs the supported diversion handoff.
apt-get install -y --allow-remove-essential \
    coreutils-from-gnu coreutils-from-uutils-
apt-get check

if ! is_installed build-essential \
    || ! is_installed coreutils-from-gnu \
    || is_installed coreutils-from-uutils; then
    printf 'error: package transition did not complete\n' >&2
    exit 1
fi
installed_build_essential_depends=$(dpkg-query -W -f='${Depends}' build-essential)
if [[ $installed_build_essential_depends == *coreutils-from-uutils* \
    || $installed_build_essential_depends != *coreutils* ]]; then
    printf 'error: installed build-essential has unexpected dependencies: %s\n' \
        "$installed_build_essential_depends" >&2
    exit 1
fi
if ! /usr/bin/ls --version 2>/dev/null | awk 'NR == 1 { found = /GNU coreutils/ } END { exit !found }'; then
    printf 'error: /usr/bin/ls is not provided by GNU coreutils after the transition\n' >&2
    exit 1
fi

printf 'Transition complete.\n'
printf '  build-essential: %s\n' "$(dpkg-query -W -f='${Version}' build-essential)"
printf '  selector:        coreutils-from-gnu %s\n' "$(dpkg-query -W -f='${Version}' coreutils-from-gnu)"
printf '  active ls:       %s\n' "$(readlink -f /usr/bin/ls)"
