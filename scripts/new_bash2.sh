#!/bin/bash

# bug_hunt.sh
# Custom script for automated bug hunting
# Usage: ./bug_hunt.sh <URL>

TARGET_URL=$1

# Output file for storing results
OUTPUT_FILE="bug_hunt_output.txt"
touch "$OUTPUT_FILE"

# Ensure the output file is created
touch "$OUTPUT_FILE"

# Begin Bug Hunting
{
    # Resolve the IP address of the entered domain name
    IP=$(dig +short $TARGET_URL)
    echo "Scanning target IP address: $IP"
    echo -e "\n"

    echo "-------------------------------------------------------------------------------------------------------------"

    # Ping the target
    echo "Ping Results:"
    ping -c 4 $TARGET_URL
    echo -e "\n"

    echo "-------------------------------------------------------------------------------------------------------------"

    # WHOIS record
    echo "WHOIS Record:"
    whois "$TARGET_URL" | grep -E '^(Registrar|Registrant|Admin|Tech)' | tee WhoIS.txt
    echo -e "\n"

    echo "-------------------------------------------------------------------------------------------------------------"

    # Subdomain Enumeration
    echo "Subdomain Enumeration (Subfinder):"
    subfinder -silent -d $TARGET_URL | tee subdomains.txt
    echo -e "\n"

    echo "-------------------------------------------------------------------------------------------------------------"

    # Vulnerability Scan (Nikto)
    echo "Vulnerability Scan (Nikto):"
    nikto -h $TARGET_URL
    echo -e "\n"

    echo "-------------------------------------------------------------------------------------------------------------"

    # Nuclei Scan
    echo "Nuclei Vulnerability Scan:"
    nuclei -u $TARGET_URL -silent
    echo -e "\n"

    echo "-------------------------------------------------------------------------------------------------------------"

    # XSS Testing (XSStrike)
    echo "XSS Testing (XSStrike):"
    xsstrike -u $TARGET_URL --automate
    echo -e "\n"

    echo "-------------------------------------------------------------------------------------------------------------"

    # SQL Injection Testing (SQLmap)
    echo "SQL Injection Testing (SQLmap):"
    sqlmap -u $TARGET_URL --batch --risk=3 --level=5
    echo -e "\n"

    echo "-------------------------------------------------------------------------------------------------------------"

    # Directory Bruteforce (Gobuster)
    echo "Directory Bruteforce (Gobuster):"
    gobuster dir -u $TARGET_URL -w /usr/share/wordlists/dirb/common.txt
    echo -e "\n"

    echo "-------------------------------------------------------------------------------------------------------------"

    # Traceroute
    echo "Running traceroute for $TARGET_URL"
    traceroute $TARGET_URL
    echo -e "\n"

    # DNS Records Fetch
    echo "Fetching DNS records for $TARGET_URL"
    dig +short $TARGET_URL
    echo -e "\n"

    echo "Custom bug hunt completed for $TARGET_URL"
} 2>&1 | tee -a "$OUTPUT_FILE"
