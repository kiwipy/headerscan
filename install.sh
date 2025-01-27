#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

VERSION=$(grep 'VERSION=' hscan.py | sed 's/^.*=//')
if [[ $VERSION == *"\""* ]];then
    VERSION=${VERSION:1:-1}
fi
echo "*** Installing HeaderScan v$VERSION ***"

# Program files (always install)
install -C -D -m 755 -v hscan.py /usr/local/bin/hscan

# Config files (install if not exist)

echo "Done."
