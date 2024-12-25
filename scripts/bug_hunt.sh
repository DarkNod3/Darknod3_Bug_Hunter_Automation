#!/bin/bash

# bug_hunt.sh
# Custom script for domain reconnaissance
# Usage: ./bug_hunt.sh <URL>

TARGET_URL=$1


# Output file for storing results
OUTPUT_FILE="bug_hunt_output.txt"
touch "$OUTPUT_FILE"

# Ensure the output file is created
touch "$OUTPUT_FILE"

# Begin Reconnaissance
{
    # Resolve the IP address of the entered domain name
    IP=$(dig +short $TARGET_URL)
    echo "Scanning target IP address: $IP"
    echo -e "\n"

    echo -e "${CYAN}-------------------------------------------------------------------------------------------------------------${RESET}"

    # Ping the target
    echo "Ping Results:"
    ping -c 4 $TARGET_URL
    echo -e "\n"

    echo -e "${CYAN}---------------------------------------------------------------------------------------------------------------${RESET}"

    # WHOIS record
    echo "WHOIS Record:"
    whois "$TARGET_URL" | grep -E '^(Registrar|Registrant|Admin|Tech)' | tee WhoIS.txt
    echo -e "\n"
    sleep .5

    echo -e "${CYAN}----------------------------------------------------------------------------------------------------------------${RESET}"

    # MX record
    echo "MX Record:"
    dig +short MX "$TARGET_URL"
    echo -e "\n"
    sleep .5

    echo -e "${CYAN}-----------------------------------------------------------------------------------------------------------------${RESET}"

    # CNAME record
    echo "CNAME Record:"
    dig +short CNAME "$TARGET_URL"
    echo -e "\n"
    sleep .5

    echo -e "${CYAN}------------------------------------------------------------------------------------------------------------------${RESET}"

    # SPF record
    echo "SPF Record:"
    dig +short TXT "$TARGET_URL" | grep -E 'v=spf1'
    echo -e "\n"
    sleep .5

    # Print results in a formatted way
    echo "------------------------------------------------------------------------------------------------------------"
    printf "| %-4s | %-15s | %-25s | %-50s |\n" "S.No" "Record Type" "Record" "Details"
    echo "------------------------------------------------------------------------------------------------------------"

    SN=1

    # Print WHOIS results
    echo "WHOIS Record:"
    whois "$TARGET_URL" | grep -E '^(Registrar|Registrant|Admin|Tech)' | while IFS= read -r line; do
        printf "| %-4s | %-15s | %-25s | %-50s |\n" "$SN" "WHOIS" "$TARGET_URL" "$line"
        ((SN++))
    done

    # Print MX results
    echo "MX Record:"
    dig +short MX "$TARGET_URL" | while IFS= read -r line; do
        printf "| %-4s | %-15s | %-25s | %-50s |\n" "$SN" "MX" "$TARGET_URL" "$line"
        ((SN++))
    done

    # Print CNAME results
    echo "CNAME Record:"
    dig +short CNAME "$TARGET_URL" | while IFS= read -r line; do
        printf "| %-4s | %-15s | %-25s | %-50s |\n" "$SN" "CNAME" "$TARGET_URL" "$line"
        ((SN++))
    done

    # Print SPF results
    echo "SPF Record:"
    dig +short TXT "$TARGET_URL" | grep -E 'v=spf1' | while IFS= read -r line; do
        printf "| %-4s | %-15s | %-25s | %-50s |\n" "$SN" "SPF" "$TARGET_URL" "$line"
        ((SN++))
    done

    echo "------------------------------------------------------------------------------------------------------------"
    echo -e "\e[3mDomain Initial Recon Over\e[0m"
    sleep .5

    # Additional commands from Code 2 (traceroute and DNS fetch)
    echo "Running traceroute for $TARGET_URL"
    traceroute $TARGET_URL

    echo "Fetching DNS records for $TARGET_URL"
    dig +short $TARGET_URL

    echo "Custom bug hunt completed for $TARGET_URL"
} 2>&1 | tee -a "$OUTPUT_FILE"
