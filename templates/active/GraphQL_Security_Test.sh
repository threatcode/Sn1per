#!/bin/bash
# GraphQL Security Testing Tool
# Description: Tests for common GraphQL security vulnerabilities
# Author: Sn1per
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default values
TARGET_URL=""
WORDLIST="/usr/share/wordlists/dirb/common.txt"
OUTPUT_FILE="graphql_audit_$(date +%Y%m%d_%H%M%S).json"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT=10

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
        exit 1
    fi
}

# Print banner
print_banner() {
    echo -e "${YELLOW}"
    echo "   _____                 _       _   _   _ ___ "
    echo "  / ____|               | |     | | | | | |__ \\"
    echo " | |  __ _ __ __ _ _ __ | |__   | |_| | | |  ) |"
    echo " | | |_ | '__/ _\` | '_ \| '_ \\  | __| | | | / / "
    echo " | |__| | | | (_| | |_) | | | | | |_| |_| |/ /_ "
    echo "  \_____|_|  \\__,_| .__/|_| |_|  \\__|\___//_/(_)"
    echo "                  | |                             "
    echo "                  |_|                             "
    echo -e "\n  GraphQL Security Testing Tool - Sn1per${NC}\n"
}

# Check for GraphQL endpoint
discover_endpoint() {
    echo -e "${YELLOW}[*] Checking for GraphQL endpoint...${NC}"
    
    local common_paths=(
        "/graphql"
        "/graphiql"
        "/graphql/console"
        "/api"
        "/api/graphql"
        "/gql"
        "/query"
    )
    
    local found=0
    
    for path in "${common_paths[@]}"; do
        local url="${TARGET_URL%/}${path}"
        local response=$(curl -s -i -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" --connect-timeout $TIMEOUT -m $TIMEOUT -d '{"query":"{__schema{types{name}}}"}' "$url" 2>/dev/null)
        
        if [[ $response == *"200 OK"* ]] && [[ $response == *"__schema"* ]]; then
            echo -e "${GREEN}[+] Found GraphQL endpoint: $url${NC}"
            TARGET_URL="$url"
            found=1
            break
        fi
        
        # Also check GET requests
        response=$(curl -s -i -X GET -H "User-Agent: $USER_AGENT" --connect-timeout $TIMEOUT -m $TIMEOUT "$url?query={__schema{types{name}}}" 2>/dev/null)
        
        if [[ $response == *"200 OK"* ]] && [[ $response == *"__schema"* ]]; then
            echo -e "${GREEN}[+] Found GraphQL endpoint (GET): $url${NC}"
            TARGET_URL="$url"
            found=1
            break
        fi
    done
    
    if [ $found -eq 0 ]; then
        echo -e "${YELLOW}[!] Could not find GraphQL endpoint using common paths${NC}"
        echo -e "${YELLOW}[*] You can specify the full URL with -u${NC}"
        return 1
    fi
    
    return 0
}

# Test for introspection
test_introspection() {
    echo -e "\n${YELLOW}[*] Testing for GraphQL introspection...${NC}"
    
    local intro_query='{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}\nfragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}\nfragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}\nfragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}\n"}'
    
    local response=$(curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" --connect-timeout $TIMEOUT -m $TIMEOUT -d "$intro_query" "$TARGET_URL" 2>/dev/null)
    
    if [[ $response == *"__schema"* ]]; then
        echo -e "${RED}[!] WARNING: GraphQL introspection is enabled${NC}"
        
        # Save introspection schema
        local schema_file="graphql_schema_$(echo $TARGET_URL | sed 's/[^a-zA-Z0-9]/_/g').json"
        echo "$response" | jq . > "$schema_file"
        echo -e "${YELLOW}[*] Introspection schema saved to: $schema_file${NC}"
        
        # Check for sensitive information in schema
        local sensitive_fields=$(echo "$response" | grep -iE 'password|secret|token|key|api[_-]?key|auth|credential|private')
        
        if [ -n "$sensitive_fields" ]; then
            echo -e "${RED}[!] WARNING: Potentially sensitive field names found in schema:${NC}"
            echo "$sensitive_fields" | sort | uniq | sed 's/^/  - /'
        fi
    else
        echo -e "${GREEN}[+] GraphQL introspection is disabled${NC}"
    fi
}

# Test for batch operations
test_batch_operations() {
    echo -e "\n${YELLOW}[*] Testing for batch operations...${NC}"
    
    local batch_payload='[{"query":"{__typename}"},{"query":"{__typename}"}]'
    local response=$(curl -s -i -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" --connect-timeout $TIMEOUT -m $TIMEOUT -d "$batch_payload" "$TARGET_URL" 2>/dev/null)
    
    if [[ $response == *"__typename"* ]]; then
        echo -e "${RED}[!] WARNING: Batch operations are enabled${NC}"
        echo -e "${YELLOW}[*] This could lead to denial of service or bypassing rate limits${NC}"
    else
        echo -e "${GREEN}[+] Batch operations are disabled${NC}"
    fi
}

# Test for CSRF protection
test_csrf() {
    echo -e "\n${YELLOW}[*] Testing for CSRF protection...${NC}"
    
    # First check if it's a GET endpoint
    local response=$(curl -s -i -X GET -H "User-Agent: $USER_AGENT" --connect-timeout $TIMEOUT -m $TIMEOUT "${TARGET_URL}?query={__typename}" 2>/dev/null)
    
    if [[ $response == *"__typename"* ]]; then
        echo -e "${YELLOW}[!] WARNING: GraphQL accepts GET requests${NC}"
        echo -e "${YELLOW}[*] This could make the API vulnerable to CSRF attacks${NC}"
    else
        echo -e "${GREEN}[+] GraphQL does not accept GET requests${NC}"
    fi
    
    # Check for CSRF tokens
    response=$(curl -s -i -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" --connect-timeout $TIMEOUT -m $TIMEOUT -d '{"query":"{__typename}"}' "$TARGET_URL" 2>/dev/null)
    
    if [[ $response == *"csrf"* || $response == *"xsrf"* || $response == *"x-csrf-token"* ]]; then
        echo -e "${GREEN}[+] CSRF protection headers found${NC}"
    else
        echo -e "${YELLOW}[!] No CSRF protection headers detected${NC}"
    fi
}

# Test for SQL/NoSQL injection
test_injection() {
    echo -e "\n${YELLOW}[*] Testing for injection vulnerabilities...${NC}"
    
    # Test for SQL injection
    local sql_payloads=(
        "' OR '1'='1"
        "' OR 1=1--"
        '" OR "1"="1'"
        '" OR 1=1--'"
        "1; DROP TABLE users--"
    )
    
    # Test for NoSQL injection
    local nosql_payloads=(
        '"$ne":"non_existent"'
        '"$gt":{}'
        '"$where":"1 == 1"'
        '"$or":[{"1":"1"},{"1":"1"}]'
    )
    
    echo -e "${YELLOW}[*] Testing SQL injection...${NC}"
    for payload in "${sql_payloads[@]}"; do
        local query="{\"query\":\"{search(query: \\\"$payload\\\") {id name}}\"}"
        local response=$(curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" --connect-timeout $TIMEOUT -m $TIMEOUT -d "$query" "$TARGET_URL" 2>/dev/null)
        
        if [[ $response == *"syntax error"* || $response == *"SQL"* || $response == *"error"* ]]; then
            echo -e "${RED}[!] Possible SQL injection with payload: $payload${NC}"
        fi
    done
    
    echo -e "\n${YELLOW}[*] Testing NoSQL injection...${NC}"
    for payload in "${nosql_payloads[@]}"; do
        local query="{\"query\":\"{search(filter: {$payload}) {id name}}\"}"
        local response=$(curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" --connect-timeout $TIMEOUT -m $TIMEOUT -d "$query" "$TARGET_URL" 2>/dev/null)
        
        if [[ $response == *"Mongo"* || $response == *"syntax"* || $response == *"error"* ]]; then
            echo -e "${RED}[!] Possible NoSQL injection with payload: $payload${NC}"
        fi
    done
    
    echo -e "\n${YELLOW}[*] Injection testing completed${NC}"
}

# Test for rate limiting
test_rate_limiting() {
    echo -e "\n${YELLOW}[*] Testing for rate limiting...${NC}"
    
    local response1=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" --connect-timeout $TIMEOUT -m $TIMEOUT -d '{"query":"{__typename}"}' "$TARGET_URL" 2>/dev/null)
    
    if [ "$response1" != "200" ]; then
        echo -e "${YELLOW}[-] Initial request failed with status: $response1${NC}"
        return
    fi
    
    # Send 10 rapid requests
    local success=0
    for i in {1..10}; do
        local response=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" --connect-timeout $TIMEOUT -m $TIMEOUT -d '{"query":"{__typename}"}' "$TARGET_URL" 2>/dev/null)
        
        if [ "$response" == "200" ]; then
            ((success++))
        fi
    done
    
    if [ $success -eq 10 ]; then
        echo -e "${RED}[!] WARNING: No rate limiting detected (10/10 requests succeeded)${NC}"
    else
        echo -e "${GREEN}[+] Rate limiting appears to be enabled ($((10 - success))/10 requests were blocked)${NC}"
    fi
}

# Main function
main() {
    print_banner
    check_tools
    
    # Parse command line arguments
    while getopts "u:w:o:t:h" opt; do
        case $opt in
            u) TARGET_URL="$OPTARG" ;;
            w) WORDLIST="$OPTARG" ;;
            o) OUTPUT_FILE="$OPTARG" ;;
            t) TIMEOUT="$OPTARG" ;;
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
    
    echo -e "${YELLOW}=== GraphQL Security Audit ===${NC}"
    echo -e "Target: ${TARGET_URL}"
    echo -e "Date: $(date)\n"
    
    # Try to discover GraphQL endpoint if not provided directly
    if [[ ! $TARGET_URL =~ /(graphql|gql|api|query)$ ]]; then
        discover_endpoint
        if [ $? -ne 0 ]; then
            exit 1
        fi
    fi
    
    # Run all tests
    test_introspection
    test_batch_operations
    test_csrf
    test_injection
    test_rate_limiting
    
    echo -e "\n${YELLOW}=== Audit Complete ===${NC}"
    echo -e "Results saved to: ${OUTPUT_FILE}"
}

# Print usage
usage() {
    echo "Usage: $0 -u <target-url> [-w wordlist] [-o output-file] [-t timeout]"
    echo "Options:"
    echo "  -u <target-url>  Base URL of the target application (required)"
    echo "  -w <wordlist>    Path to wordlist for endpoint discovery (default: /usr/share/wordlists/dirb/common.txt)"
    echo "  -o <output-file> Output file (default: graphql_audit_<timestamp>.json)"
    echo "  -t <timeout>     Request timeout in seconds (default: 10)"
    echo "  -h               Show this help message"
    exit 1
}

# Execute main function
main "$@"

exit 0
