#!/bin/bash

# whoxy_lookup.sh
# Script to fetch domain WHOIS and ownership history using WhoXY API
# Usage: ./whoxy_lookup.sh <DOMAIN>

# Check if the domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <DOMAIN>"
    exit 1
fi

DOMAIN=$1

# Your WhoXY API Key
API_KEY="YOUR_WHOXY_API_KEY"

# Base URL for WhoXY API
BASE_URL="https://api.whoxy.com"

# Function to fetch WHOIS information
fetch_whois_info() {
    echo "Fetching WHOIS details for domain: $DOMAIN"
    RESPONSE=$(curl -s "${BASE_URL}/?key=${API_KEY}&whois=${DOMAIN}")

    if [[ $(echo "$RESPONSE" | grep -o '"status":"success"') ]]; then
        echo "$RESPONSE" | jq '.' > "whoxy_whois_${DOMAIN}.json"
        echo "WHOIS details saved to whoxy_whois_${DOMAIN}.json"
    else
        echo "Failed to fetch WHOIS details. Response:"
        echo "$RESPONSE" | jq '.'
    fi
}

# Function to fetch ownership history
fetch_domain_history() {
    echo "Fetching ownership history for domain: $DOMAIN"
    RESPONSE=$(curl -s "${BASE_URL}/?key=${API_KEY}&history=${DOMAIN}")

    if [[ $(echo "$RESPONSE" | grep -o '"status":"success"') ]]; then
        echo "$RESPONSE" | jq '.' > "whoxy_history_${DOMAIN}.json"
        echo "Ownership history saved to whoxy_history_${DOMAIN}.json"
    else
        echo "Failed to fetch ownership history. Response:"
        echo "$RESPONSE" | jq '.'
    fi
}

# Main function
main() {
    echo "Starting domain lookup for: $DOMAIN"
    fetch_whois_info
    fetch_domain_history
    echo "Domain lookup completed for: $DOMAIN"
}

# Execute main function
main
