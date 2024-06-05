#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi
echo "*** Installing HeaderScan $(grep 'VERSION=' headerscan.sh | sed 's/^.*=//') ***"

# Program files (always install)
install -C -D -m 755 -v headerscan.sh /usr/local/bin/headerscan

# Config files (install if not exist)
if [ ! -f "/usr/local/share/headerscan/keyword_list" ];then
    mkdir -pv /usr/local/share/headerscan
    echo "creating file /usr/local/share/headerscan/keyword_list"
    touch /usr/local/share/headerscan/keyword_list
    chmod 777 /usr/local/share/headerscan/keyword_list
    #install -C -D -m 777 -v keyword_list /usr/local/share/headerscan/keyword_list
fi
echo "Done."
