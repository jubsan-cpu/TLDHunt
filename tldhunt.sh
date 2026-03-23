#!/bin/bash

# Color definitions
: "${blue:=\033[0;34m}"
: "${cyan:=\033[0;36m}"
: "${reset:=\033[0m}"
: "${red:=\033[0;31m}"
: "${green:=\033[0;32m}"
: "${orange:=\033[0;33m}"
: "${bold:=\033[1m}"
: "${b_green:=\033[1;32m}"
: "${b_red:=\033[1;31m}"
: "${b_orange:=\033[1;33m}"

# Default values
nreg=false
update_tld=false
tld_file="tlds.txt"
tld_url="https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

# Check if whois is installed
command -v whois &> /dev/null || { echo "whois not installed. You must install whois to use this tool." >&2; exit 1; }

# Check if curl is installed (needed for TLD update)
command -v curl &> /dev/null || { echo "curl not installed. You must install curl to use this tool." >&2; exit 1; }

# Banner
cat << "EOF"
 _____ _    ___  _  _          _   
|_   _| |  |   \| || |_  _ _ _| |_ 
  | | | |__| |) | __ | || | ' \  _|
  |_| |____|___/|_||_|\_,_|_||_\__|
        Domain Availability Checker
EOF

usage() {
    echo "Usage: $0 -k <keyword> [-e <tld> | -E <tld-file>] [-x] [--update-tld]"
    echo "       $0 -d <domain-file> [-o <output-file>] [-x]"
    echo "Example: $0 -k linuxsec -E tlds.txt"
    echo "       : $0 -d domains.txt -o available.txt"
    echo "       : $0 --update-tld"
    exit 1
}

# Argument parsing
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -k|--keyword) keyword="$2"; shift ;;
        -d|--domain-file) domain_file="$2"; shift ;;
        -o|--output) output_file="$2"; shift ;;
        -e|--tld) tld="$2"; shift ;;
        -E|--tld-file) exts="$2"; shift ;;
        -x|--not-registered) nreg=true ;;
        --update-tld) update_tld=true ;;
        *) echo "Unknown parameter passed: $1"; usage ;;
    esac
    shift
done

# Validate arguments
if [[ "$update_tld" = true ]]; then
    [[ -n $keyword || -n $tld || -n $exts || "$nreg" = true ]] && { echo "--update-tld cannot be used with other flags."; usage; }
    echo "Fetching TLD data from $tld_url..."
    curl -s "$tld_url" | \
        grep -v '^#' | \
        tr '[:upper:]' '[:lower:]' | \
        sed 's/^/./' > "$tld_file"
    echo "TLDs have been saved to $tld_file."
    exit 0
fi

# Map TLD to the correct whois server
get_whois_server() {
    local tld="${1##*.}"
    case "$tld" in
        com|net) echo "whois.verisign-grs.com" ;;
        org) echo "whois.pir.org" ;;
        info) echo "whois.afilias.net" ;;
        io) echo "whois.nic.io" ;;
        co) echo "whois.nic.co" ;;
        dev|app) echo "whois.nic.google" ;;
        xyz) echo "whois.nic.xyz" ;;
        me) echo "whois.nic.me" ;;
        *) echo "" ;;
    esac
}

# Function to check domain availability
check_domain() {
    local domain="$1"
    local whois_server whois_output
    whois_server=$(get_whois_server "$domain")

    if [[ -n $whois_server ]]; then
        whois_output=$(whois -h "$whois_server" "$domain" 2>/dev/null)
    else
        whois_output=$(whois "$domain" 2>/dev/null)
    fi

    local not_found
    not_found=$(echo "$whois_output" | grep -iE "^No match|^NOT FOUND|^No Data Found|^Domain not found|^No entries found|^Status: free|^% No such domain")

    if [[ -n $not_found ]]; then
        echo -e "[${b_green}avail${reset}] $domain"
        [[ -n $output_file ]] && echo "$domain" >> "$output_file"
    else
        if [[ "$nreg" = false ]]; then
            local expiry_date
            expiry_date=$(echo "$whois_output" | grep -iE "Expiry Date|Expiration Date|Registry Expiry Date|Expiration Time" | grep -Eo '[0-9]{4}-[0-9]{2}-[0-9]{2}' | uniq)
            if [[ -n $expiry_date ]]; then
                echo -e "[${b_red}taken${reset}] $domain - Exp Date: ${orange}$expiry_date${reset}"
            else
                echo -e "[${b_red}taken${reset}] $domain - No expiry date found"
            fi
        fi
    fi
}

# Bulk domain file mode
if [[ -n $domain_file ]]; then
    [[ -n $keyword || -n $tld || -n $exts ]] && { echo "-d cannot be used with -k, -e, or -E."; usage; }
    [[ ! -f $domain_file ]] && { echo "Domain file $domain_file not found."; exit 1; }
    [[ -n $output_file ]] && : > "$output_file"
    while IFS= read -r domain || [[ -n $domain ]]; do
        [[ -z $domain || $domain == \#* ]] && continue
        [[ $domain != *.* ]] && domain="${domain}.com"
        check_domain "$domain" &
        if (( $(jobs -r -p | wc -l) >= 30 )); then
            wait -n
        fi
    done < "$domain_file"
    wait
    exit 0
fi

# Validate arguments
[[ -z $keyword ]] && { echo "Keyword is required."; usage; }
[[ -n $tld && -n $exts ]] && { echo "You can only specify one of -e or -E options."; usage; }
[[ -z $tld && -z $exts ]] && { echo "Either -e or -E option is required."; usage; }
[[ -n $exts && ! -f $exts ]] && { echo "TLD file $exts not found."; usage; }

# Load TLDs
tlds=()
if [[ -n $exts ]]; then
    readarray -t tlds < "$exts"
else
    tlds=("$tld")
fi

# Process TLDs
for ext in "${tlds[@]}"; do
    domain="$keyword$ext"
    check_domain "$domain" &
    if (( $(jobs -r -p | wc -l) >= 30 )); then
        wait -n
    fi
done
wait