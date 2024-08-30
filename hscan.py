#!/usr/bin/env python3
#
# Application: HeaderScan
# Comment:     Parse and scan email header
# Copyright:   William Andersson 2024
# Website:     https://github.com/william-andersson
# License:     GPL
#
VERSION="1.0.3"
import sys
import os
import re
import shutil
import string

if sys.version_info < (3, 6):
    print("Requires python 3.6 or higher.")
    sys.exit(1)

base64 = "no"
marks = 0
general = []
other = []
helo = []
received = []
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
    global general, other, from_addr, reply_addr, spf, \
           dkim, dmarc, helo, spf_domain, spf_ip, received

    with open("/tmp/hscan/parsed", "r") as subject:
        for line in subject:
            words = line.split()
            if len(words) > 0 and words[0] != "-----":
                if words[0] in ["Date:", "From:", "To:", "Subject:"]:
                    general.append(line.rstrip("\n"))
                    if words[0] == "From:":
                        from_addr = words[-1].strip("<").rstrip(">")
                elif words[0] in ["MIME-Version:", "Return-Path:", 
                                  "Reply-To:", "Message-ID:"]:
                    other.append(line.rstrip("\n"))
                    if words[0] == "Reply-To:":
                        reply_addr = words[-1].strip("<").rstrip(">")
                elif words[0] == "Authentication-Results:":
                    for word in words:
                        if "spf=" in word:
                            spf = word.split("=")[-1]
                        elif "dkim=" in word:
                            dkim = word.split("=")[-1]
                        elif "dmarc=" in word:
                            dmarc = word.split("=")[-1]
                elif words[0] == "Received-SPF:" and "spf_tmp" not in locals():
                    spf_tmp = words[5].split(".")[-2:]
                    spf_domain = (f"{spf_tmp[0]}.{spf_tmp[1]}")
                    spf_ip = words[7]
                    for word in words:
                        if "helo=" in word:
                            helo.append(word.split("=")[-1].rstrip(";"))
                elif words[0] == "Received:":
                    for word in words:
                        if "helo=" in word:
                            helo.append(word.split("=")[-1].rstrip(")"))
                    received.append(words)


def get_ip_info(ip, color):
    # Parse and print info for IP address
    os.system(f"curl -s https://ipinfo.io/{ip} > /tmp/hscan/ipinfo")
    output = {}

    with open("/tmp/hscan/ipinfo", "r") as subject:
        for line in subject:
            if ":" in line:
                for words in line.split(",  "):
                    word = words.split(": ")
                    add_key = word[0].strip(" \"").rstrip("\"")
                    add_val = word[1].strip(" \"").rstrip(",\n\"")
                    output[add_key] = add_val

    if "bogon" in output:
        if output['bogon'] == 'true':
            print(f"  |                  {ORANGE_BOLD}IP: " \
                  f"Bogon address reserved for special use.{END}")
    else:
        for key, value in output.items():
            if color == "red":
                if key in ["ip", "city", "country", "org", "timezone"]:
                    if key == "org":
                        print(f"  |                  {RED}" \
                              f"{key} = {value.partition(' ')[2]}{END}")
                    else:
                        print(f"  |                  {RED}" \
                              f"{key} = {value}{END}")
            else:
                if key in ["city", "country", "org", "timezone"]:
                    if key == "org":
                        print(f"  |                  {key}" \
                              f" = {value.partition(' ')[2]}")
                    else:
                        print(f"  |                  {key} = {value}")
        

def print_summery():
    global marks
    TOT_MARKS = 9
    verdict = []

    print("[General info]")
    for item in general:
        print(f"  {item}")
    print("\n[Other info]")
    for item in other:
        print(f"  {item}")

    print("\n[Authentication]")
    if spf != "pass":
        print(f"  SPF: {RED_BOLD}{spf}{END}")
        verdict.append("  - SPF not passed.")
        marks += 1
    else:
        print(f"  SPF: {spf}")
    if dkim != "pass":
        print(f"  DKIM: {RED_BOLD}{dkim}{END}")
        verdict.append("  - DKIM not passed.")
        marks += 1
    else:
        print(f"  DKIM: {dkim}")
    if dmarc != "pass":
        print(f"  DMARC: {RED_BOLD}{dmarc}{END}")
        verdict.append("  - DMARC not passed.")
        marks += 1
    else:
        print(f"  DMARC: {dmarc}")
    
    print("\n[HELO strings]")
    for addr in helo:
        if "." in addr:
            print(f"  HELO: {BLUE_BOLD}{addr}{END}")
        else:
            print(f"  HELO: {RED_BOLD}{addr}{END}")
            verdict.append("  - HELO string without domain.")
            marks += 1
    
    print("\n[Received-SPF]")
    print(f"  Received-SPF: {BLUE_BOLD}{spf_domain}{END} ({spf_ip})")
    
    print("\n[Email path through network]")
    print("  |-(Receiver)")
    for id in received:
        if id[1] != "by":
            ip = id[3].strip("(").rstrip(")")
            if_ip = id[2].strip("[").rstrip("]")
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', if_ip):
                # If domain name is IP address.
                print(f"  |  {RED_BOLD}{id[0]} {id[1]}: " \
                      f"Source without URL --> {if_ip}{END}")
                get_ip_info(if_ip, "red")
                verdict.append("  - Received from without domain name.")
                marks += 1
            elif re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                # If IPV4 Look up domain IP.
                if ip == spf_ip:
                    if spf_domain in id[2]:
                        if id[2] not in helo:
                            verdict.append("  - Received from domain " \
                                           "not in HELO.")
                            print(f"  |  {id[0]} {id[1]}: " \
                                  f"{RED_BOLD}{id[2]}{END} {id[3]}")
                            marks += 1
                        else:
                            print(f"  |  {id[0]} {id[1]}: " \
                                  f"{BLUE_BOLD}{id[2]}{END} {id[3]}")
                    else:
                        verdict.append("  - Received from not same " \
                                       "domain as SPF.")
                        print(f"  |  {id[0]} {id[1]}: " \
                              f"{RED_BOLD}{id[2]}{END} {id[3]}")
                        marks += 1
                print(f"  |              {id[4]}: {id[5]}")
                get_ip_info(ip, "none")
            elif "localhost" in id[2]:
                # If domain name = localhost
                print(f"  |  {ORANGE_BOLD}{id[0]} {id[1]}: " \
                      f"Source without URL --> {id[2]}{END}")
                verdict.append("  - Received from localhost.")
                marks += 1
            else:
                print(f"  |  {id[0]} {id[1]}: {id[2]}")
                print(f"  |              {id[4]}: {id[5]}")
    print("  |-(Sender)")

    if 'reply_addr' in globals():
        if reply_addr != from_addr:
            marks += 1
            verdict.append("  - REPLY address not same as FROM.")
    
    print("\n[Verdict]")
    if marks < 2:
        print(f"  {BLUE_BOLD}Number of suspect features: " \
              f"{marks}/{TOT_MARKS}{END}")
    elif marks < int(TOT_MARKS/2):
        print(f"  {ORANGE_BOLD}Number of suspect features: " \
              f"{marks}/{TOT_MARKS}{END}")
    else:
        print(f"  {RED_BOLD}Number of suspect features: " \
              f"{marks}/{TOT_MARKS}{END}")
    for note in verdict:
        print(note)
    print("\n  ********************************************************\n" \
          "  * THIS APPLICATION IS ONLY A TOOL FOR DISPLAYING EMAIL *\n" \
          "  * HEADER INFORMATION IN AN EASY TO READ FORMAT.        *\n" \
          "  * ULTIMATELY IT'S THE USER THAT HAS TO DECIDE WHETHER  *\n" \
          "  * THE EMAIL IS AUTHENTIC AND OR SAFE OR NOT.           *\n" \
          "  ********************************************************")
  
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
