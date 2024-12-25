#!/bin/bash

TOOL_NAME=$1
API_PROVIDER=$2
API_KEY=$3

if [ "$TOOL_NAME" == "subfinder" ]; then
    echo "Installing Subfinder..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
elif [ "$TOOL_NAME" == "httpx" ]; then
    echo "Installing HTTPX..."
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
elif [ "$TOOL_NAME" == "nuclei" ]; then
    echo "Installing Nuclei..."
    sudo apt install nuclei -y
elif [ "$TOOL_NAME" == "amass" ]; then
    echo "Installing Amass..."
    go install -v github.com/owasp-amass/amass/v3/...@latest
elif [ "$TOOL_NAME" == "sublist3r" ]; then
    echo "Installing Sublist3r..."
    git clone https://github.com/aboul3la/Sublist3r.git sublist3r
    cd sublist3r
    sudo apt update
    sudo apt install python3-pip -y
    pip3 install -r requirements.txt
elif [ "$TOOL_NAME" == "sublist3r_install_api" ]; then
    echo "Installing Sublist3r with API Key..."
    git clone https://github.com/aboul3la/Sublist3r.git sublist3r
    cd sublist3r
    sudo apt update
    sudo apt install python3-pip -y
    pip3 install -r requirements.txt

    CONFIG_FILE="/home/kali/.config/subfinder/provider-config.yaml"
    if [ -n "$API_PROVIDER" ] && [ -n "$API_KEY" ]; then
        echo "Updating API key for $API_PROVIDER..."
        if grep -q "$API_PROVIDER" "$CONFIG_FILE"; then
            sed -i "s|$API_PROVIDER:.*|$API_PROVIDER: [$API_KEY]|" "$CONFIG_FILE"
        else
            echo "$API_PROVIDER: [$API_KEY]" >> "$CONFIG_FILE"
        fi
        echo "API Key updated successfully."
    else
        echo "API Provider or Key missing!"
    fi
else
    echo "Unknown tool: $TOOL_NAME"
    exit 1
fi
