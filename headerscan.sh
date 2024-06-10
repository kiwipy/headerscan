#!/bin/bash
#
# Application: HeaderScan
# Comment:     Parse and scan email header
# Copyright:   William Andersson 2024
# Website:     https://github.com/william-andersson
# License:     GPL
#
VERSION=0.9.0

if [ -z "$1" ];then
    echo "No input file provided!"
    exit 1
fi

OUT="$(mktemp /tmp/ipinfo.XXXX)"
PARSED="$(mktemp /tmp/headerscan.XXXX)"
BASE64="$(mktemp /tmp/base64.XXX)"
ASCII="$(mktemp /tmp/ascii.XXX)"
MARKS_LOG="$(mktemp /tmp/marks.XXX)"
MARKS=0
AVAIL_MARKS=0
for match in $(cat /usr/local/bin/headerscan | awk '/MARKS=\$\(\(MARKS\+1\)\)/' );do
    AVAIL_MARKS=$((AVAIL_MARKS+1))
done

decode_base64(){
    for line in $(cat $1 | sed -n '/Content-Transfer-Encoding: base64/,$p');do
        if [[ "$line" == *"--"* ]];then
            SKIP="1"
        elif [[ "$line" == *"base64"* ]];then
            SKIP="0"
        fi
        if [ "$SKIP" != "1" ] && [ "$line" != "Content-Transfer-Encoding:" ];then
            if [[ "$line" != *"base64"* ]];then
                echo $line >> $BASE64
            else
                echo "" >> $BASE64
            fi
        fi
    done

    base64 -w0 -d $BASE64 > $ASCII
}

parse_input_file(){
    # Update keyword_list
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

    # Parse to file
    echo "----- Parse file for HeaderScan v$VERSION -----" >> $PARSED
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
            echo -e "\n\n----- Email content below, not included in parse file -----" >> $PARSED
            break
        elif [ "$y" == "1" ];then
            echo -en "\n\n$i " >> $PARSED
        else
            echo -n "$i " >> $PARSED
        fi
    done
}

get_ip_info(){
    # Collect info about ip-address
    curl -s https://ipinfo.io/$1 > $OUT

    IP="$(cat $OUT | grep "\"ip\":" | cut -f4- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"
    CITY="$(cat $OUT | grep "\"city\":" | cut -f4- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"
    COUNTRY="$(cat $OUT | grep "\"country\":" | cut -f4- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"
    PROVIDER="$(cat $OUT | grep "\"org\":" | cut -f5- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"
    TIME="$(cat $OUT | grep "\"timezone\":" | cut -f4- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"
    BOGON="$(cat $OUT | grep "\"bogon\":" | cut -f4- -d ' ' | sed 's/\"//g' | sed 's/\,//g')"

    if [ "$2" == "red" ];then
        if [ "$BOGON" == "true" ];then
            echo -e "\e[1;33m  |                  IP: Bogon address reserved for special use.\033[0m"
        else
            echo -e "\033[31m  |                  IP: $IP\n  |                  Location: $CITY, $COUNTRY\n  |                  Timezone: $TIME\n  |                  Provider: $PROVIDER\033[0m"
        fi
    else
        echo -e "  |                  Location: $CITY, $COUNTRY\n  |                  Timezone: $TIME\n  |                  Provider: $PROVIDER"
    fi
}

parse_input_file $1

# Print email main info
echo "[General info]"
echo "  $(cat $PARSED | awk '/^Date: /')"
echo "  $(cat $PARSED | awk '/^From: /')"
echo "  $(cat $PARSED | awk '/^To: /')"
echo "  $(cat $PARSED | awk '/^Subject: /')"
echo -e "\n[Other info]"
echo "  $(cat $PARSED | awk '/^MIME-Version: /')"
echo "  $(cat $PARSED | awk '/^Return-Path: / {print $1, $2}')"
REPLY="$(cat $PARSED | awk '/^Reply-To: /')"
if [ ! -z "$REPLY" ];then
    echo "  $REPLY"
    if [[ $(cat $PARSED | awk '/^From: /') != *"$(echo $REPLY | awk '{print $NF}')"* ]];then
        MARKS=$((MARKS+1))
        echo "  - REPLY address not same as FROM." >> $MARKS_LOG
    fi
fi
echo "  $(cat $PARSED | awk '/^Message-ID: /')"

# Print Authentication-Results
echo -e "\n[Authentication]"
SPF="$(cat $PARSED | awk '/^Authentication-Results: /' | grep -o '[^ ]*spf=[^ ]*' | cut -d "=" -f2)"
DKIM="$(cat $PARSED | awk '/^Authentication-Results: /' | grep -o '[^ ]*dkim=[^ ]*' | cut -d "=" -f2)"
DMARC="$(cat $PARSED | awk '/^Authentication-Results: /' | grep -o '[^ ]*dmarc=[^ ]*' | cut -d ";" -f2 | cut -d "=" -f2)"
if [ "$SPF" != "pass" ];then
    echo -e "  SPF: \e[1;31m$SPF\033[0m"
    MARKS=$((MARKS+1))
    echo "  - SPF not passed." >> $MARKS_LOG
else
    echo "  SPF: $SPF"
fi
if [ "$DKIM" != "pass" ];then
    echo -e "  DKIM: \e[1;31m$DKIM\033[0m"
    MARKS=$((MARKS+1))
    echo "  - DKIM not passed." >> $MARKS_LOG
else
    echo "  DKIM: $DKIM"
fi
if [ "$DMARC" != "pass" ];then
    echo -e "  DMARC: \e[1;31m$DMARC\033[0m"
    MARKS=$((MARKS+1))
    echo "  - DMARC not passed." >> $MARKS_LOG
else
    echo "  DMARC: $DMARC"
fi

# Print helo strings
echo -e "\n[HELO strings]"
for helo in $(cat $PARSED | grep -o '[^ ]*helo=[^ ]*' | cut -d "=" -f2 | sed 's/.\{1\}$//');do
    if [[ $helo != *"."* ]];then
        echo -e "  HELO: \e[1;31m$helo\033[0m"
        MARKS=$((MARKS+1))
        echo "  - HELO string without domain." >> $MARKS_LOG
    else
        echo -e "  HELO: \e[1;34m$helo\033[0m"
    fi
    HELO="${HELO} $helo"
done

# Print Received-SPF info
echo -e "\n[Received-SPF]"
SPF_DOM=$(cat $PARSED | awk '/^Received-SPF: / {print $6}')
SPF_IP=$(cat $PARSED | awk '/^Received-SPF: / {print $8}')
SPF_SHORT_DOM="$(echo $SPF_DOM | rev | cut -d "." -f-2 | rev)"
echo -e "  Received-SPF: \e[1;34m$SPF_DOM\033[0m $SPF_IP"

# Print all Received: fields
echo -e "\n[Email path through network]"
echo "  |-(Receiver)"
for i in $(cat $PARSED | awk '/Received: from/ {print $3}' | sed 's/\[//g' | sed 's/\]//g');do
    # If $i is a IP, print waring and look-up
    if [[ $i =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "\e[1;31m  |  Received: From: Source without URL --> $i\033[0m"
        MARKS=$((MARKS+1))
        echo "  - Received from without domain name." >> $MARKS_LOG
        get_ip_info $i red
    elif [[ $i == *"localhost"* ]];then
        echo -e "\e[1;33m  |  Received: From: Source without URL --> $i\033[0m"
        MARKS=$((MARKS+1))
        echo "  - Received from localhost." >> $MARKS_LOG
    else
        # Print ip after every host if exists
        HOST_IP=$(host $i | awk 'NR==1{print $4}')
        if [ "$HOST_IP" == "$SPF_IP" ];then
            if [[ $i == *"$SPF_SHORT_DOM"* ]];then
                if [[ $i == *"$HELO"* ]];then
                    echo -e "  |  Received: From: \e[1;31m$i\033[0m $HOST_IP"
                    MARKS=$((MARKS+1))
                    echo "  - Received from domain not in HELO." >> $MARKS_LOG
                else
                    echo -e "  |  Received: From: \e[1;34m$i\033[0m $HOST_IP"
                fi                
            else
                echo -e "  |  Received: From: \e[1;31m$i\033[0m $HOST_IP"
                MARKS=$((MARKS+1))
                echo "  - Received from not same domain as SPF." >> $MARKS_LOG
            fi
            echo "  |              By: $(cat $PARSED | awk '/Received: from '$i'/ {print $6}')"
        else
            echo "  |  Received: From: $i $HOST_IP"
            echo "  |              By: $(cat $PARSED | awk '/Received: from '$i'/ {print $6}')"
        fi
        if [ "$HOST_IP" != "found:" ];then
            get_ip_info $HOST_IP
        fi
    fi
done
echo "  |-(Sender)"

echo -e "\n[Verdict]"
if [ $MARKS -lt 2 ];then
    echo -e "\e[1;34m  Number of suspect features: $MARKS/$AVAIL_MARKS\033[0m"
elif [ $MARKS -lt $(($AVAIL_MARKS/2)) ];then
    echo -e "\e[1;33m  Number of suspect features: $MARKS/$AVAIL_MARKS\033[0m"
else
    echo -e "\e[1;31m  Number of suspect features: $MARKS/$AVAIL_MARKS\033[0m"
fi
cat $MARKS_LOG

echo ""
read -e -p "Save parsed file to path (return to skip): " DEST
if [ ! -z $DEST ];then
    if [ -d $DEST ];then
        NAME="$(cat $PARSED | awk '/^From: / {print $NF}' | cut -d "@" -f2 | cut -d "." -f1)"
        cp $PARSED ${DEST%/}/headerscan-$NAME-$(date +%H%M%S)
    else
        echo "No such directory!"
    fi
fi

decode_base64 $1
if [ -s $ASCII ];then
    read -p "View base64 encodings [y/n]?: " BASE
    if [ "$BASE" == "Y" ] || [ "$BASE" == "y" ];then
        nano $ASCII
    fi
else
    echo "No embedded base64 encodings."
fi

rm $OUT $PARSED $BASE64 $ASCII $MARKS_LOG
