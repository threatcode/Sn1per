#!/bin/bash
# API OAuth 2.0 Security Checker
# Description: Checks for common OAuth 2.0 misconfigurations in API endpoints
# Author: Sn1per
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default values
TARGET_URL=""
OUTPUT_FILE="oauth_audit_$(date +%Y%m%d_%H%M%S).json"
VERBOSE=false
TIMEOUT=10
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Check if required tools are installed
check_tools() {
    local missing=0
    for tool in curl jq; do
        if ! command -v $tool &> /dev/null; then
            echo -e "${RED}[!] Error: $tool is not installed${NC}"
            missing=1
        fi
    done
    
    if [ $missing -ne 0 ]; then
        echo -e "${YELLOW}[*] Please install the missing tools and try again.${NC}"
        echo "On Debian/Ubuntu: sudo apt-get install curl jq"
        echo "On macOS: brew install curl jq"
        exit 1
    fi
}

# Print banner
print_banner() {
    echo -e "${YELLOW}"
    echo "   ___  _____  _    _   _    _     ___  _   _ _____ "
    echo "  / _ \|  __ \| |  | | | |  | |   / _ \| \ | |_   _|"
    echo " / /_\ \ |  \/| |  | | | |  | |  / /_\ \  \| | | |  "
    echo " |  _  | | __ | |/\| | | |/\| | |  _  | . \` | | |  "
    echo " | | | | |_\ \\  /\  /  \  /\  /_| | | | |\  |_| |_ "
    echo " \_| |_/\____/ \/  \/    \/  \/\_\_| |_\_| \_/\___/ "
    echo -e "\n  OAuth 2.0 Security Scanner - Sn1per${NC}\n"
}

# Send HTTP request
send_request() {
    local url="$1"
    local method="${2:-GET}"
    local headers="${3:-}"
    local data="${4:-}"
    
    local cmd="curl -s -i -X $method -A \"$USER_AGENT\" --connect-timeout $TIMEOUT -m $TIMEOUT"
    
    # Add headers if provided
    if [ -n "$headers" ]; then
        cmd+=" $headers"
    fi
    
    # Add data if provided (for POST requests)
    if [ -n "$data" ]; then
        cmd+=" -d \"$data\""
    fi
    
    # Add URL and execute
    cmd+=" \"$url\""
    
    if [ "$VERBOSE" = true ]; then
        echo -e "${YELLOW}[*] Executing: $cmd${NC}" >&2
    fi
    
    eval "$cmd"
}

# Check OAuth endpoints
discover_oauth_endpoints() {
    local base_url="$1"
    local endpoints=()
    
    # Common OAuth 2.0 endpoints
    local common_paths=(
        "/.well-known/oauth-authorization-server"
        "/.well-known/openid-configuration"
        "/oauth/authorize"
        "/oauth/token"
        "/oauth2/authorize"
        "/oauth2/token"
        "/auth/oauth/authorize"
        "/auth/oauth/token"
        "/api/oauth/authorize"
        "/api/oauth/token"
        "/identity/connect/authorize"
        "/identity/connect/token"
    )
    
    echo -e "${YELLOW}[*] Discovering OAuth 2.0 endpoints...${NC}"
    
    for path in "${common_paths[@]}"; do
        local url="${base_url%/}${path}"
        local response=$(send_request "$url" "HEAD")
        
        if [[ $response == *"200 OK"* || $response == *"301 Moved Permanently"* || $response == *"302 Found"* ]]; then
            echo -e "${GREEN}[+] Found: $url${NC}"
            endpoints+=("$url")
        elif [ "$VERBOSE" = true ]; then
            echo -e "${YELLOW}[-] Not found: $url${NC}"
        fi
    done
    
    if [ ${#endpoints[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No OAuth 2.0 endpoints found using common paths${NC}"
    fi
    
    echo ""
    return ${#endpoints[@]}
}

# Check for misconfigured token validation
check_token_validation() {
    local token_endpoint="$1"
    local auth_server="$2"
    
    echo -e "${YELLOW}[*] Testing token validation...${NC}"
    
    # Test 1: Check if token endpoint requires authentication
    local response=$(send_request "$token_endpoint" "POST")
    
    if [[ $response == *"200 OK"* ]]; then
        echo -e "${RED}[!] WARNING: Token endpoint may not require client authentication${NC}"
    else
        echo -e "${GREEN}[+] Token endpoint requires authentication${NC}"
    fi
    
    # Test 2: Check for token replay
    echo -e "\n${YELLOW}[*] Testing for token replay...${NC}"
    echo -e "${YELLOW}[*] This test requires a valid access token. Please enter one (or press Enter to skip):${NC}"
    read -r access_token
    
    if [ -n "$access_token" ]; then
        # Test if token is still valid after being used
        local auth_header="-H \"Authorization: Bearer $access_token\""
        local userinfo_url="${auth_server%/}/userinfo"
        
        # First request (should work)
        echo -e "${YELLOW}[*] Testing token validity...${NC}"
        response=$(send_request "$userinfo_url" "GET" "$auth_header")
        
        if [[ $response == *"200 OK"* ]]; then
            echo -e "${GREEN}[+] Token is valid${NC}"
            
            # Second request (should still work if not one-time use)
            response2=$(send_request "$userinfo_url" "GET" "$auth_header")
            
            if [[ $response2 == *"200 OK"* ]]; then
                echo -e "${YELLOW}[!] WARNING: Token may support replay attacks (not one-time use)${NC}"
            else
                echo -e "${GREEN}[+] Token appears to be one-time use${NC}"
            fi
        else
            echo -e "${YELLOW}[!] Token is not valid or userinfo endpoint not available${NC}"
        fi
    else
        echo -e "${YELLOW}[*] Skipping token replay test - no token provided${NC}"
    fi
}

# Check for insecure redirect URIs
check_redirect_uris() {
    local auth_endpoint="$1"
    
    echo -e "\n${YELLOW}[*] Testing for open redirect vulnerabilities...${NC}"
    
    # Common open redirect test patterns
    local test_params=(
        "redirect_uri=http://evil.com"
        "redirect_uri=https://evil.com"
        "redirect_uri=//evil.com"
        "redirect_uri=/\evil.com"
        "redirect_uri=http:\\evil.com"
        "redirect_uri=https:\\evil.com"
        "redirect_uri=javascript:alert(1)"
    )
    
    for param in "${test_params[@]}"; do
        local test_url="${auth_endpoint}?${param}&response_type=code&client_id=test&scope=openid%20profile"
        local response=$(send_request "$test_url" "GET")
        
        if [[ $response == *"302 Found"* ]] && [[ $response == *"Location: http://evil.com"* || $response == *"Location: https://evil.com"* ]]; then
            echo -e "${RED}[!] VULNERABLE: Open redirect found with parameter: $param${NC}"
        elif [ "$VERBOSE" = true ]; then
            echo -e "${GREEN}[+] No open redirect with: $param${NC}"
        fi
    done
}

# Check for weak token signing algorithms
check_token_signing() {
    local jwks_uri="$1"
    
    echo -e "\n${YELLOW}[*] Checking token signing algorithms...${NC}"
    
    if [ -z "$jwks_uri" ]; then
        echo -e "${YELLOW}[*] No JWKS URI provided, skipping algorithm check${NC}"
        return
    fi
    
    local response=$(send_request "$jwks_uri" "GET")
    
    if [[ $response == *"200 OK"* ]]; then
        local keys=$(echo "$response" | grep -A 1000 '^{' | grep -B 1000 '^}')  # Extract JSON part
        
        if [ -n "$keys" ]; then
            echo "$keys" | jq .
            
            # Check for weak algorithms
            if echo "$keys" | grep -q '"alg":\s*"HS256\|none"'; then
                echo -e "${RED}[!] WARNING: Weak or no algorithm (HS256 or 'none') found in JWKS${NC}"
            else
                echo -e "${GREEN}[+] No weak algorithms found in JWKS${NC}"
            fi
        else
            echo -e "${YELLOW}[!] Could not parse JWKS response${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Could not retrieve JWKS from $jwks_uri${NC}"
    fi
}

# Check for token leakage in URLs
check_token_leakage() {
    echo -e "\n${YELLOW}[*] Checking for token leakage in browser history...${NC}"
    echo -e "${YELLOW}[*] This is a manual check. Look for access tokens in the following locations:${NC}"
    echo "- Browser history"
    echo "- Browser cache"
    echo "- Server logs"
    echo "- Network proxies"
    echo "- Referrer headers"
    echo -e "${YELLOW}[*] Check if tokens are passed in URLs (fragment/hash is safer than query parameters)${NC}"
}

# Main function
main() {
    print_banner
    check_tools
    
    # Parse command line arguments
    while getopts "t:o:vh" opt; do
        case $opt in
            t) TARGET_URL="$OPTARG" ;;
            o) OUTPUT_FILE="$OPTARG" ;;
            v) VERBOSE=true ;;
            h) usage ;;
            *) usage ;;
        esac
    done
    
    # Validate parameters
    if [ -z "$TARGET_URL" ]; then
        echo -e "${RED}[!] Error: Target URL is required${NC}"
        usage
    fi
    
    # Ensure URL starts with http:// or https://
    if [[ ! $TARGET_URL =~ ^https?:// ]]; then
        TARGET_URL="https://$TARGET_URL"
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    
    # Redirect output to file and console
    exec > >(tee -a "$OUTPUT_FILE") 2>&1
    
    echo -e "${YELLOW}=== OAuth 2.0 Security Audit ===${NC}"
    echo -e "Target: ${TARGET_URL}"
    echo -e "Date: $(date)\n"
    
    # Discover OAuth endpoints
    discover_oauth_endpoints "$TARGET_URL"
    
    # If we found endpoints, perform additional checks
    if [ $? -gt 0 ]; then
        echo -e "${YELLOW}[*] Running additional security checks...${NC}"
        
        # For demonstration, we'll use the base URL - in a real scan, you'd parse the discovery document
        local auth_endpoint="${TARGET_URL%/}/oauth2/authorize"
        local token_endpoint="${TARGET_URL%/}/oauth2/token"
        local jwks_uri="${TARGET_URL%/}/.well-known/jwks.json"
        
        check_token_validation "$token_endpoint" "$TARGET_URL"
        check_redirect_uris "$auth_endpoint"
        check_token_signing "$jwks_uri"
        check_token_leakage
    fi
    
    echo -e "\n${YELLOW}=== Audit Complete ===${NC}"
    echo -e "Results saved to: ${OUTPUT_FILE}"
}

# Print usage
usage() {
    echo "Usage: $0 -t <target-url> [-o output-file] [-v]"
    echo "Options:"
    echo "  -t <target-url>  Base URL of the target application (required)"
    echo "  -o <output-file> Output file (default: oauth_audit_<timestamp>.json)"
    echo "  -v               Enable verbose output"
    echo "  -h               Show this help message"
    exit 1
}

# Execute main function
main "$@"

exit 0
