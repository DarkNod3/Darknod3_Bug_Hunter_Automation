#!/bin/bash

# Advanced Recon Script
# Combines subdomain enumeration, SSL/TLS scan, port scan, HTTP probing, and grading
# Usage: ./new_bash2.sh <domain>

# Check and install required tools
required_tools=(jq sslscan nmap sublist3r curl)
for tool in "${required_tools[@]}"; do
    if ! command -v $tool &>/dev/null; then
        echo "$tool is not installed. Installing..."
        sudo apt update && sudo apt install -y $tool
    fi
done

TARGET_URL=$1

if [[ -z "$TARGET_URL" ]]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DESKTOP_PATH="$HOME/Desktop"
OUTPUT_FILE="${DESKTOP_PATH}/${TARGET_URL}_scan_results.txt"
SUBDOMAIN_FILE="${DESKTOP_PATH}/${TARGET_URL}_subdomains.txt"

touch "$OUTPUT_FILE" "$SUBDOMAIN_FILE"

echo "Dark Nod3 2.0 - Advanced Recon"
echo "Starting scan for domain: $TARGET_URL" | tee -a "$OUTPUT_FILE"

IP=$(dig +short A "$TARGET_URL")
IP=${IP:-"N/A"}
echo "Target IP Address: $IP" | tee -a "$OUTPUT_FILE"

# Enumerate subdomains or fallback to target if none found
echo "Enumerating subdomains for $TARGET_URL..." | tee -a "$OUTPUT_FILE"
sublist3r -d "$TARGET_URL" -o "$SUBDOMAIN_FILE" 2>/dev/null
if [[ ! -s "$SUBDOMAIN_FILE" ]]; then
    echo "$TARGET_URL" > "$SUBDOMAIN_FILE"
    echo "No subdomains found. Using the target domain for further analysis." | tee -a "$OUTPUT_FILE"
else
    echo "Subdomains have been saved to $SUBDOMAIN_FILE." | tee -a "$OUTPUT_FILE"
fi

echo "--------------------------------------------------------------------------------------------------------------------------------------------------------" | tee -a "$OUTPUT_FILE"
printf "| %-4s | %-30s | %-8s | %-8s | %-8s | %-8s | %-8s | %-8s | %-6s | %-6s | %-20s | %-15s | %-10s |
" \
    "S.No" "Subdomain" "SSLv2" "SSLv3" "TLSv1.0" "TLSv1.1" "TLSv1.2" "TLSv1.3" "SSL" "Hdr" "Open Ports" "IP Address" "Status" | tee -a "$OUTPUT_FILE"
echo "--------------------------------------------------------------------------------------------------------------------------------------------------------" | tee -a "$OUTPUT_FILE"

SN=1

# Function to fetch SSL grade
fetch_ssl_grade() {
    local subdomain=$1
    SSL_LABS_API="https://api.ssllabs.com/api/v3/analyze?host=$subdomain"
    retries=3
    for ((i=1; i<=retries; i++)); do
        result=$(curl -s "$SSL_LABS_API" | jq -r '.endpoints[0].grade' 2>/dev/null)
        if [[ -n "$result" && "$result" != "null" ]]; then
            echo "$result"
            return
        fi
        sleep 5
    done
    echo "N/A"
}

# Function to fetch security header grade (alternative approach)
fetch_security_header_grade() {
    local subdomain=$1
    SECURITY_HEADER_URL="https://securityheaders.com/"
    retries=3

    for ((i=1; i<=retries; i++)); do
        # Send the request and save the response
        response=$(curl -s --data "q=$subdomain&followRedirects=on" "$SECURITY_HEADER_URL")
        echo "$response" > /tmp/security_header_response.html

        # Parse the grade using xmllint
        grade=$(echo "$response" | xmllint --html --xpath 'string(//strong[contains(text(), "Grade:")]/following-sibling::span)' - 2>/dev/null)

        if [[ -n "$grade" ]]; then
            echo "$grade"
            return
        fi

        # Retry if no grade found
        sleep 5
    done

    echo "N/A"
}


# Read subdomains and perform checks
while IFS= read -r SUBDOMAIN; do
    SUBDOMAIN_IP=$(dig +short A "$SUBDOMAIN" 2>/dev/null | head -n1)
    SUBDOMAIN_IP=${SUBDOMAIN_IP:-"N/A"}

    # HTTP probe
    STATUS_CODE=$(curl -o /dev/null -s -w "%{http_code}" "$SUBDOMAIN" || echo "N/A")

    # SSL/TLS version support
    SSL_SCAN_RESULTS=$(sslscan "$SUBDOMAIN" 2>/dev/null)
    declare -A PROTOCOLS=(["SSLv2"]="N/A" ["SSLv3"]="N/A" ["TLSv1.0"]="N/A" ["TLSv1.1"]="N/A" ["TLSv1.2"]="N/A" ["TLSv1.3"]="N/A")
    if [[ -n "$SSL_SCAN_RESULTS" ]]; then
        for PROTOCOL in "${!PROTOCOLS[@]}"; do
            if echo "$SSL_SCAN_RESULTS" | grep -q "$PROTOCOL.*disabled"; then
                PROTOCOLS[$PROTOCOL]="Disabled"
            elif echo "$SSL_SCAN_RESULTS" | grep -q "$PROTOCOL.*enabled"; then
                PROTOCOLS[$PROTOCOL]="Enabled"
            fi
        done
    fi

    # SSL grade and security header grade
    SSL_GRADE=$(fetch_ssl_grade "$SUBDOMAIN")
    HEADER_GRADE=$(fetch_security_header_grade "$SUBDOMAIN")

    # Port scan
    OPEN_PORTS=$(nmap -sS -F "$SUBDOMAIN" 2>/dev/null | grep open | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')
    OPEN_PORTS=${OPEN_PORTS:-"N/A"}

    # Print the results
    printf "| %-4s | %-30s | %-8s | %-8s | %-8s | %-8s | %-8s | %-8s | %-6s | %-6s | %-20s | %-15s | %-10s |
" \
        "$SN" "$SUBDOMAIN" "${PROTOCOLS[SSLv2]}" "${PROTOCOLS[SSLv3]}" "${PROTOCOLS[TLSv1.0]}" "${PROTOCOLS[TLSv1.1]}" "${PROTOCOLS[TLSv1.2]}" "${PROTOCOLS[TLSv1.3]}" "$SSL_GRADE" "$HEADER_GRADE" "$OPEN_PORTS" "$SUBDOMAIN_IP" "$STATUS_CODE" | tee -a "$OUTPUT_FILE"

    ((SN++))
done < "$SUBDOMAIN_FILE"

echo "--------------------------------------------------------------------------------------------------------------------------------------------------------" | tee -a "$OUTPUT_FILE"
echo "Scan completed. Results saved in $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
