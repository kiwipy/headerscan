#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi
echo "*** Uninstalling HeaderScan from system ***"
rm -v /usr/local/bin/hscan
echo "Done."
