#!/bin/bash
#
# Application: HeaderScan
# Comment:     Parse and scan email header
# Copyright:   William Andersson 2024
# Website:     https://github.com/william-andersson
# License:     GPL
#
VERSION=0.1.0

echo "------------ HeaderScan v$VERSION ------------"
OUT="$(mktemp /tmp/ipinfo.XXXX)"
PARSED="$(mktemp /tmp/head-scan.XXXX)"

parse_input_file(){
    #
    # Update keyword_list
    #
    for a in $(grep -i "^[A-Z]" $1 | awk '{print $1}');do
        if [[ "$a" =~ [A-Z] ]];then
            b=${a%?}':'
                if [ "$a" == "$b" ];then
                    if ! $(grep -Fxq "$a" /usr/local/share/headerscan/keyword_list);then
                        if [[ $a != *"="* ]];then
                            echo $a >> /usr/local/share/headerscan/keyword_list
                        fi
                    fi
                fi
        fi
    done

    #
    # Parse to file
    #
    for i in $(cat $1);do
        y="0"
        for x in $(cat /usr/local/share/headerscan/keyword_list);do
            if [ "$i" == "$x" ];then
                y="1"
            fi
        done
        if [ "$i" == "MIME-Version:" ];then
            STOP="1"
            echo -en "\n\n$i " >> $PARSED
        elif [ "$STOP" == "1" ];then
            echo -n "$i " >> $PARSED
            echo -e "\n\n----- Email content below, not included in parsed file -----" >> $PARSED
            break
        elif [ "$y" == "1" ];then
            echo -en "\n\n$i " >> $PARSED
        else
            echo -n "$i " >> $PARSED
        fi
    done
}

get_ip_info(){
    #
    # Collect info about ip
    #
    curl -s https://ipinfo.io/$1 > $OUT

    IP="$(cat $OUT | grep "\"ip\":" | cut -f4- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"
    CITY="$(cat $OUT | grep "\"city\":" | cut -f4- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"
    COUNTRY="$(cat $OUT | grep "\"country\":" | cut -f4- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"
    PROVIDER="$(cat $OUT | grep "\"org\":" | cut -f5- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"
    TIME="$(cat $OUT | grep "\"timezone\":" | cut -f4- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"
    BOGON="$(cat $OUT | grep "\"bogon\":" | cut -f4- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"

    if [ "$2" == "red" ];then
        if [ "$BOGON" == "true" ];then
            echo -e "\033[33m  IP: Bogon address reserved for special use.\033[0m"
        else
            echo -e "\033[31m  IP: $IP\n  Location: $CITY, $COUNTRY\n  Timezone: $TIME\n  Provider: $PROVIDER\033[0m"
        fi
    else
        echo -e "  Location: $CITY, $COUNTRY\n  Timezone: $TIME\n  Provider: $PROVIDER"
    fi
}

parse_input_file $1
# Print email main info
echo "$(cat $PARSED | awk '/^Date: /')"
echo "$(cat $PARSED | awk '/^From: /')"
echo "$(cat $PARSED | awk '/^To: /')"
echo "$(cat $PARSED | awk '/^Subject: /')"
echo ""
echo "$(cat $PARSED | awk '/^Return-Path: / {print $1, $2}')"
echo "$(cat $PARSED | awk '/^Message-ID: /')"
echo "$(cat $PARSED | awk '/^MIME-Version: /')"
echo ""

# Print Authentication-Results
echo "SPF: $(cat $PARSED | grep -o '[^ ]*spf=[^ ]*' | cut -d "=" -f2)"
echo "DKIM: $(cat $PARSED | grep -o '[^ ]*dkim=[^ ]*' | cut -d "=" -f2)"
echo "DMARC: $(cat $PARSED | grep -o '[^ ]*dmarc=[^ ]*' | cut -d ";" -f2 | cut -d "=" -f2)"
echo ""
for helo in $(cat $PARSED | grep -o '[^ ]*helo=[^ ]*' | cut -d "=" -f2 | sed 's/.\{1\}$//');do
    echo "HELO: $helo"
done
echo ""

# Print Received-SPF info
SPF_DOM=$(cat $PARSED | awk '/^Received-SPF: / {print $6}')
SPF_IP=$(cat $PARSED | awk '/^Received-SPF: / {print $8}')
echo -e "Received-SPF: \033[34m$SPF_DOM\033[0m ($SPF_IP)"


# Print all Received: fields
for i in $(cat $PARSED | awk '/Received: from/ {print $3}' | sed 's/\[//g' | sed 's/\]//g');do
    # If $i is a IP, print waring and look-up
    if [[ $i =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "\033[31mReceived: Source without URL --> $i\033[0m"
        get_ip_info $i red
    else
        # Print ip after every host if exists
        HOST_IP=$(host $i | awk 'NR==1{print $4}')
        if [ "$HOST_IP" == "$SPF_IP" ];then
            echo -e "Received: \033[34m$i\033[0m $(host $i | awk 'NR==1{print $3, $4}')"
        else
            echo "Received: $i $(host $i | awk 'NR==1{print $3, $4}')"
        fi
        if [ "$HOST_IP" != "found:" ];then
            get_ip_info $HOST_IP
        fi
    fi
done

echo ""
read -e -p "Save parsed file to: " DEST
if [ ! -z $DEST ];then
    cp $PARSED ${DEST%/}/header-$(date +%d-%m-%Y_%H:%M)
fi
rm $OUT
rm $PARSED
