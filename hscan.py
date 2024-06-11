#!/usr/bin/env python3
#
# Application: HeaderScan
# Comment:     Parse and scan email header
# Copyright:   William Andersson 2024
# Website:     https://github.com/william-andersson
# License:     GPL
#
VERSION="1.0.1"
import sys
import os
import re
import shutil
import string

base64 = "no"
MARKS = 0
GENERAL = []
OTHER = []
HELO = []
RECEIVED = []
RED = '\033[31m'
RED_BOLD = '\033[31m\033[1m'
BLUE_BOLD = '\033[34m\033[1m'
ORANGE_BOLD = '\033[33m\033[1m'
END = '\033[0m'

if len(sys.argv) > 1:
    if os.path.isfile(sys.argv[1]):
        input_file = sys.argv[1]
        if os.path.isdir("/tmp/hscan/"):
            shutil.rmtree("/tmp/hscan/")
            os.mkdir("/tmp/hscan/")
        else:
            os.mkdir("/tmp/hscan/")
    else:
        print("No such file.")
        sys.exit(1)
else:
    print("Usage: hscan </path/to/header-file>")
    sys.exit(1)

def parse_file():
    # Parse input file, extract and decode base64.
    parsed_file = open("/tmp/hscan/parsed", "w")
    base64_file = open("/tmp/hscan/base64", "w")
    parsed_stat = "null"
    base64_stat = "null"
    global base64
    with open(input_file, "r") as subject:
        parsed_file.write(f"----- Parse file for HeaderScan v{VERSION} -----")
        for line in subject:
            if parsed_stat != "EOF":
                # Parse input file
                for word in line.split():
                    if word.endswith(":") and word[0].isupper():
                        parsed_file.write(f"\n\n{word} ")
                    else:
                        if parsed_stat == "done":
                            parsed_file.write(f"{word}\n")
                            parsed_file.write(f"----- Email content below, " \
                                              f"not included in parse file " \
                                              f"-----\n")
                            parsed_file.close()
                            parsed_stat = "EOF"
                        else:
                            parsed_file.write(f"{word} ")
                    if word == "MIME-Version:":
                        parsed_stat = "done"
            else:
                # Parse and decode base64 encodings
                if line.startswith("Content-Transfer-Encoding: base64"):
                    base64 = "yes"
                    base64_stat = "write"
                elif line.startswith("--"):
                    base64_stat = "skip"
                if base64_stat == "write" and not \
                    line.startswith("Content-Transfer-Encoding: base64"):
                    base64_file.write(f"{line}")
                else:
                    pass
    base64_file.close()
    if base64 == "yes":
        os.system("base64 -w0 -d /tmp/hscan/base64 > /tmp/hscan/text64")
    
    
def collect_data():
    # Collect data from parsed file.
    global GENERAL, OTHER, FROM_ADDR, REPLY_ADDR, SPF, \
           DKIM, DMARC, HELO, SPF_DOMAIN, SPF_IP, RECEIVED
    with open("/tmp/hscan/parsed", "r") as subject:
        for line in subject:
            words = line.split()
            if len(words) > 0 and words[0] != "-----":
                if words[0] in ["Date:", "From:", "To:", "Subject:"]:
                    GENERAL.append(line.rstrip("\n"))
                    if words[0] == "From:":
                        FROM_ADDR = words[-1].strip("<").rstrip(">")
                elif words[0] in ["MIME-Version:", "Return-Path:", 
                                  "Reply-To:", "Message-ID:"]:
                    OTHER.append(line.rstrip("\n"))
                    if words[0] == "Reply-To:":
                        REPLY_ADDR = words[-1].strip("<").rstrip(">")
                elif words[0] == "Authentication-Results:":
                    for word in words:
                        if "spf=" in word:
                            SPF = word.split("=")[-1]
                        elif "dkim=" in word:
                            DKIM = word.split("=")[-1]
                        elif "dmarc=" in word:
                            DMARC = word.split("=")[-1]
                elif words[0] == "Received-SPF:":
                    SPF_TMP = words[5].split(".")[-2:]
                    SPF_DOMAIN = (f"{SPF_TMP[0]}.{SPF_TMP[1]}")
                    SPF_IP = words[7]
                    for word in words:
                        if "helo=" in word:
                            HELO.append(word.split("=")[-1].rstrip(";"))
                elif words[0] == "Received:":
                    for word in words:
                        if "helo=" in word:
                            HELO.append(word.split("=")[-1].rstrip(")"))
                    RECEIVED.append(words)


def get_ip_info(IP, COLOR):
    # Parse and print info for IP address
    os.system(f"curl -s https://ipinfo.io/{IP} > /tmp/hscan/ipinfo")
    OUTPUT = {}
    with open("/tmp/hscan/ipinfo", "r") as subject:
        for line in subject:
            if ":" in line:
                for words in line.split(",  "):
                    word = words.split(": ")
                    KEY = word[0].strip(" \"").rstrip("\"")
                    VAL = word[1].strip(" \"").rstrip(",\n\"")
                    OUTPUT[KEY] = VAL
    if "bogon" in OUTPUT:
        if OUTPUT['bogon'] == 'true':
            print(f"  |                  {ORANGE_BOLD}IP: " \
                  f"Bogon address reserved for special use.{END}")
    else:
        for key, value in OUTPUT.items():
            if COLOR == "red":
                if key in ["ip", "city", "country", "org", "timezone"]:
                    if key == "org":
                        print(f"  |                  " \
                              f"{RED}{key} = {value.partition(' ')[2]}{END}")
                    else:
                        print(f"  |                  " \
                              f"{RED}{key} = {value}{END}")
            else:
                if key in ["city", "country", "org", "timezone"]:
                    if key == "org":
                        print(f"  |                  " \
                              f"{key} = {value.partition(' ')[2]}")
                    else:
                        print(f"  |                  {key} = {value}")
        

def print_summery():
    global MARKS
    TOT_MARKS = 9
    VERDICT = []
    print("[General info]")
    for item in GENERAL:
        print(f"  {item}")
    print("\n[Other info]")
    for item in OTHER:
        print(f"  {item}")

    print("\n[Authentication]")
    if SPF != "pass":
        print(f"  SPF: {RED_BOLD}{SPF}{END}")
        VERDICT.append("  - SPF not passed.")
        MARKS += 1
    else:
        print(f"  SPF: {SPF}")
    if DKIM != "pass":
        print(f"  DKIM: {RED_BOLD}{DKIM}{END}")
        VERDICT.append("  - DKIM not passed.")
        MARKS += 1
    else:
        print(f"  DKIM: {DKIM}")
    if DMARC != "pass":
        print(f"  DMARC: {RED_BOLD}{DMARC}{END}")
        VERDICT.append("  - DMARC not passed.")
        MARKS += 1
    else:
        print(f"  DMARC: {DMARC}")
    
    print("\n[HELO strings]")
    for addr in HELO:
        if "." in addr:
            print(f"  HELO: {BLUE_BOLD}{addr}{END}")
        else:
            print(f"  HELO: {RED_BOLD}{addr}{END}")
            VERDICT.append("  - HELO string without domain.")
            MARKS += 1
    
    print("\n[Received-SPF]")
    print(f"  Received-SPF: {BLUE_BOLD}{SPF_DOMAIN}{END} ({SPF_IP})")
    
    print("\n[Email path through network]")
    print("  |-(Receiver)")
    for id in RECEIVED:
        if id[1] != "by":
            IP = id[3].strip("(").rstrip(")")
            IFIP = id[2].strip("[").rstrip("]")
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', IFIP):
                # If domain name is IP address.
                print(f"  |  {RED_BOLD}{id[0]} {id[1]}: " \
                      f"Source without URL --> {IFIP}{END}")
                get_ip_info(IFIP, "red")
                VERDICT.append("  - Received from without domain name.")
                MARKS += 1
            elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', IP):
                # If IPV4 Look up domain IP.
                if IP == SPF_IP:
                    if SPF_DOMAIN in id[2]:
                        if id[2] not in HELO:
                            VERDICT.append("  - Received from domain " \
                                           "not in HELO.")
                            print(f"  |  {id[0]} {id[1]}: " \
                                  f"{RED_BOLD}{id[2]}{END} {id[3]}")
                            MARKS += 1
                        else:
                            print(f"  |  {id[0]} {id[1]}: " \
                                  f"{BLUE_BOLD}{id[2]}{END} {id[3]}")
                    else:
                        VERDICT.append("  - Received from not same " \
                                       "domain as SPF.")
                        print(f"  |  {id[0]} {id[1]}: " \
                              f"{RED_BOLD}{id[2]}{END} {id[3]}")
                        MARKS += 1
                print(f"  |              {id[4]}: {id[5]}")
                get_ip_info(IP, "none")
            elif "localhost" in id[2]:
                # If domain name = localhost
                print(f"  |  {ORANGE_BOLD}{id[0]} {id[1]}: " \
                      f"Source without URL --> {id[2]}{END}")
                VERDICT.append("  - Received from localhost.")
                MARKS += 1
            else:
                print(f"  |  {id[0]} {id[1]}: {id[2]}")
                print(f"  |              {id[4]}: {id[5]}")
    print("  |-(Sender)")

    if 'REPLY_ADDR' in globals():
        if REPLY_ADDR != FROM_ADDR:
            MARKS += 1
            VERDICT.append("  - REPLY address not same as FROM.")
    
    print("\n[Verdict]")
    if MARKS < 2:
        print(f"  {BLUE_BOLD}Number of suspect features: " \
              f"{MARKS}/{TOT_MARKS}{END}")
    elif MARKS < int(TOT_MARKS/2):
        print(f"  {ORANGE_BOLD}Number of suspect features: " \
              f"{MARKS}/{TOT_MARKS}{END}")
    else:
        print(f"  {RED_BOLD}Number of suspect features: " \
              f"{MARKS}/{TOT_MARKS}{END}")
    for note in VERDICT:
        print(note)

  
parse_file()
collect_data()
print_summery()

print("\n")
if base64 == "yes":
    view_base64 = input("View base64 encodings [y/n]?: ")
    if view_base64 == "y":
        os.system("nano /tmp/hscan/text64")
else:
    print("No embedded base64 encodings.")
