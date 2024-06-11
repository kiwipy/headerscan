#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi
echo "*** Installing HeaderScan $(grep 'VERSION=' hscan.py | sed 's/^.*=//') ***"

# Program files (always install)
install -C -D -m 755 -v hscan.py /usr/local/bin/hscan

# Config files (install if not exist)

echo "Done."
