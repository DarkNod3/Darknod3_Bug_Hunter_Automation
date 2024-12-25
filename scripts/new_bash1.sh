#!/bin/bash
# google_dork_tool.sh
# Custom script for Google Dorking with dynamic URL integration
# Usage: sudo ./google_dork_tool.sh <TARGET_URL>

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Check if a target URL is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <TARGET_URL>"
    exit 1
fi

TARGET_URL=$1

# Paths
SCRIPTS_PATH="/home/kali/darknod3_tool/scripts"
OUTPUT_FILE="$SCRIPTS_PATH/google_dork_output.txt"
DORK_FILES=("dork1.txt" "dork2.txt" "dork3.txt")

# Extended list of User Agents
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/605.1.15"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
)

# Create output directory with proper permissions
if [ ! -d "$SCRIPTS_PATH" ]; then
    mkdir -p "$SCRIPTS_PATH"
    chown -R kali:kali "$SCRIPTS_PATH"
    chmod -R 755 "$SCRIPTS_PATH"
fi

# Create or clear output file with proper permissions
> "$OUTPUT_FILE"
chown kali:kali "$OUTPUT_FILE"
chmod 644 "$OUTPUT_FILE"

# Load dorks dynamically from files
GOOGLE_DORKS=()
for FILE in "${DORK_FILES[@]}"; do
    FULL_PATH="$SCRIPTS_PATH/$FILE"
    if [[ -f "$FULL_PATH" ]]; then
        while IFS= read -r LINE; do
            # Skip empty lines and comments
            if [[ -n "$LINE" && ! "$LINE" =~ ^[[:space:]]*# ]]; then
                # Prepend 'site:$TARGET_URL' to each dork line
                PROCESSED_DORK="site:$TARGET_URL $LINE"
                GOOGLE_DORKS+=("$PROCESSED_DORK")
            fi
        done < "$FULL_PATH"
    else
        echo "Warning: $FULL_PATH not found. Skipping..."
    fi
done

# Ensure dorks are loaded
if [ ${#GOOGLE_DORKS[@]} -eq 0 ]; then
    echo "No dorks found in the specified files. Exiting..."
    exit 1
fi

# Function to perform search with rotation and anti-blocking
perform_search() {
    local dork=$1
    local max_retries=3
    local retry_count=0
    local result=""

    while [ $retry_count -lt $max_retries ] && [ -z "$result" ]; do
        local user_agent=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}
        local encoded_dork=$(echo "$dork" | sed 's/ /+/g')
        local search_url="https://www.google.com/search?q=$encoded_dork"

        result=$(curl -s -A "$user_agent" \
            --max-time 10 \
            -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
            -H "Accept-Language: en-US,en;q=0.5" \
            -H "Connection: keep-alive" \
            "$search_url" | 
            grep -Eo 'https?://[^ ]+' | 
            grep -v "google.com" | 
            grep -v "gstatic.com" |
            grep -v "javascript:" |
            cut -d'"' -f1 | 
            head -n 3 | tr '\n' ' ')

        ((retry_count++))
        [ -z "$result" ] && sleep $(( (RANDOM % 3) + 2 ))
    done
    
    echo "$result"
}

# Function to perform Google Dork search
perform_dork_search() {
    echo "-------------------------------------------------------------------------------------------------------------"
    echo " Performing Google Dorking for: $TARGET_URL"
    echo " Output File: $OUTPUT_FILE"
    echo " Date: $(date)"
    echo "-------------------------------------------------------------------------------------------------------------" | tee -a "$OUTPUT_FILE"

    printf "| %-4s | %-100s | %-50s |\n" "S.No" "Dork Query" "Results" | tee -a "$OUTPUT_FILE"
    printf "| %-4s | %-100s | %-50s |\n" "----" "----------------------------------------------------------------------------------------------------" "--------------------------------------------------" | tee -a "$OUTPUT_FILE"

    SN=1
    total_dorks=${#GOOGLE_DORKS[@]}

    # Save cursor position for progress updates
    tput sc

    for DORK in "${GOOGLE_DORKS[@]}"; do
        # Perform search
        RESULT=$(perform_search "$DORK")

        if [ -n "$RESULT" ]; then
            # Print results if found
            printf "| %-4d | %-100s | %-50s |\n" "$SN" "$DORK" "$RESULT" | tee -a "$OUTPUT_FILE"
        fi

        # Update progress counter
        tput rc
        tput el
        echo -n "Scanning dork $SN of $total_dorks..."

        ((SN++))
        sleep 1
    done

    # Clear progress line and show completion
    echo -e "\nGoogle Dorking completed. Results saved to $OUTPUT_FILE.\n"
}

# Create sample dork file if none exists
if [ ! -f "$SCRIPTS_PATH/dork1.txt" ]; then
    cat > "$SCRIPTS_PATH/dork1.txt" << EOL
inurl:"api/v1" -github.com
inurl:"swagger.json" -github.com
inurl:"/graphql" -github.com
inurl:"/api-docs" -github.com
inurl:"/api/v2" -github.com
inurl:"/api/v3" -github.com
intext:"-----BEGIN PRIVATE KEY-----" -github.com
intext:"client_secret" -github.com
intext:"password" filetype:env -github.com
intext:"apikey" filetype:env -github.com
EOL
    chmod 644 "$SCRIPTS_PATH/dork1.txt"
fi

# Run the dorking process
perform_dork_search