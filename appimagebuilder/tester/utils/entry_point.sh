#!/bin/sh
set -e

useradd -mu $UID $UNAME

export HOME=/home/$UNAME
export XDG_DATA_DIRS=/usr/share

su $UNAME -c "$@"