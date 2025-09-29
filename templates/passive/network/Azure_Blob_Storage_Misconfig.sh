#!/bin/bash
# Azure Blob Storage Security Checker
# Description: Checks for common Azure Blob Storage misconfigurations and security issues
# Author: Sn1per
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default values
STORAGE_ACCOUNT=""
CONTAINER=""
SAS_TOKEN=""
OUTPUT_FILE="azure_blob_audit_$(date +%Y%m%d_%H%M%S).json"

# Check if Azure CLI is installed
check_azure_cli() {
    if ! command -v az &> /dev/null; then
        echo -e "${RED}[!] Error: Azure CLI is not installed${NC}"
        echo "Install it with: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
        exit 1
    fi
    
    # Check if logged in
    if ! az account show &> /dev/null; then
        echo -e "${RED}[!] Error: Not logged into Azure CLI${NC}"
        echo "Run 'az login' to authenticate"
        exit 1
    fi
}

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

# Check container public access level
check_container_access() {
    echo -e "\n${YELLOW}[*] Checking container access level...${NC}"
    
    local url="https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER}?restype=container&comp=acl"
    local headers=(
        "x-ms-version: 2020-04-08"
        "x-ms-date: $(date -u +'%a, %d %b %Y %H:%M:%S GMT')"
    )
    
    if [ -n "$SAS_TOKEN" ]; then
        url+="&${SAS_TOKEN}"
    fi
    
    local response=$(curl -s -i -X GET -H "${headers[0]}" -H "${headers[1]}" "$url" 2>/dev/null)
    
    if [[ $response == *"200 OK"* ]]; then
        local public_access=$(echo "$response" | grep -oP 'x-ms-blob-public-access: \K[^\r\n]*' || echo "None")
        
        if [ -n "$public_access" ] && [ "$public_access" != "None" ]; then
            echo -e "${RED}[!] WARNING: Container has public access level: $public_access${NC}"
            
            if [ "$public_access" == "container" ]; then
                echo -e "${RED}[!] SECURITY RISK: Container allows anonymous read access to all blobs${NC}"
            elif [ "$public_access" == "blob" ]; then
                echo -e "${YELLOW}[!] WARNING: Container allows anonymous read access to blob content${NC}"
            fi
        else
            echo -e "${GREEN}[+] Container does not have public access${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Could not determine container access level${NC}"
    fi
}

# Check for sensitive information in blobs
check_sensitive_info() {
    echo -e "\n${YELLOW}[*] Checking for sensitive information in blobs...${NC}"
    
    local url="https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER}?restype=container&comp=list"
    
    if [ -n "$SAS_TOKEN" ]; then
        url+="&${SAS_TOKEN}"
    fi
    
    local response=$(curl -s "$url" 2>/dev/null)
    
    # Common sensitive file patterns
    local sensitive_patterns=(
        '\.(pem|key|crt|p12|pfx|p7b|p7c|p7s|cer|der|csr|kdbx|kdb|keychain|keystore|jks|jceks|p8|pk8)'
        '(password|secret|key|token|credential|api[_-]?key|access[_-]?key|auth|private|confidential)\.(json|txt|env|config|conf|cfg|yml|yaml|xml|properties)'
        '(backup|dump|archive|old|save)[^/]*\.(sql|db|sqlite|sqlite3|mdb|accdb|dbf|myd|myi|frm|ibd|mdf|ldf|bak|bkp|tar|gz|zip|7z|rar)'
    )
    
    # Extract blob names from the response
    local blob_names=$(echo "$response" | grep -oP '<Name>\K[^<]+' 2>/dev/null)
    
    if [ -z "$blob_names" ]; then
        echo -e "${YELLOW}[-] No blobs found or unable to list blobs${NC}"
        return
    fi
    
    local found_sensitive=false
    
    for pattern in "${sensitive_patterns[@]}"; do
        local matches=$(echo "$blob_names" | grep -iE "$pattern")
        
        if [ -n "$matches" ]; then
            echo -e "${RED}[!] WARNING: Potentially sensitive files found matching pattern: $pattern${NC}"
            echo "$matches" | sed 's/^/  - /'
            found_sensitive=true
        fi
    done
    
    if [ "$found_sensitive" = false ]; then
        echo -e "${GREEN}[+] No obviously sensitive files detected${NC}"
    else
        echo -e "${YELLOW}[*] Review these files for sensitive information exposure${NC}"
    fi
}

# Check for CORS misconfigurations
check_cors() {
    echo -e "\n${YELLOW}[*] Checking CORS configuration...${NC}"
    
    local url="https://${STORAGE_ACCOUNT}.blob.core.windows.net/?restype=service&comp=properties"
    local headers=(
        "x-ms-version: 2020-04-08"
        "x-ms-date: $(date -u +'%a, %d %b %Y %H:%M:%S GMT')"
    )
    
    if [ -n "$SAS_TOKEN" ]; then
        url+="&${SAS_TOKEN}"
    fi
    
    local response=$(curl -s -i -X GET -H "${headers[0]}" -H "${headers[1]}" "$url" 2>/dev/null)
    
    if [[ $response == *"200 OK"* ]]; then
        local cors_rules=$(echo "$response" | grep -oP '<Cors><CorsRule>.*?</CorsRule></Cors>' 2>/dev/null)
        
        if [ -n "$cors_rules" ]; then
            echo -e "${YELLOW}[*] CORS rules found:${NC}"
            echo "$cors_rules" | sed 's/></>\n</g' | sed 's/^/  /'
            
            # Check for permissive CORS rules
            if echo "$cors_rules" | grep -q '<AllowedOrigin>\*</AllowedOrigin>'; then
                echo -e "${RED}[!] WARNING: Overly permissive CORS rule found (AllowedOrigin: *)${NC}"
            fi
            
            if echo "$cors_rules" | grep -q '<AllowedMethod>\*</AllowedMethod>'; then
                echo -e "${RED}[!] WARNING: Overly permissive CORS rule found (AllowedMethod: *)${NC}"
            fi
            
            if echo "$cors_rules" | grep -q '<AllowedHeader>\*</AllowedHeader>'; then
                echo -e "${YELLOW}[!] WARNING: Permissive CORS rule found (AllowedHeader: *)${NC}"
            fi
        else
            echo -e "${GREEN}[+] No CORS rules found (secure by default)${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Could not retrieve CORS configuration${NC}"
    fi
}

# Check for network restrictions
check_network_restrictions() {
    echo -e "\n${YELLOW}[*] Checking network restrictions...${NC}"
    
    # This requires Azure CLI and appropriate permissions
    if command -v az &> /dev/null; then
        local restrictions=$(az storage account network-rule list --account-name "$STORAGE_ACCOUNT" --query "defaultAction" -o tsv 2>/dev/null)
        
        if [ "$?" -eq 0 ]; then
            if [ "$restrictions" == "Allow" ]; then
                echo -e "${RED}[!] WARNING: Storage account allows traffic from all networks (default)${NC}"
                echo -e "${YELLOW}[*] Consider using network rules to restrict access to specific networks${NC}"
            else
                echo -e "${GREEN}[+] Storage account has network restrictions enabled${NC}"
            fi
            
            # Check if service endpoints or private endpoints are configured
            local service_endpoints=$(az storage account show --name "$STORAGE_ACCOUNT" --query 'networkRuleSet.virtualNetworkRules[].virtualNetworkResourceId' -o tsv 2>/dev/null)
            if [ -n "$service_endpoints" ]; then
                echo -e "${GREEN}[+] Virtual network service endpoints are configured${NC}"
            fi
            
            local private_endpoints=$(az network private-endpoint list --query "[?subnet.id].privateLinkServiceConnections[?privateLinkServiceId.contains(@, '$STORAGE_ACCOUNT')]" -o tsv 2>/dev/null)
            if [ -n "$private_endpoints" ]; then
                echo -e "${GREEN}[+] Private endpoints are configured${NC}"
            fi
        else
            echo -e "${YELLOW}[!] Could not retrieve network restrictions (insufficient permissions)${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Azure CLI not available for detailed network checks${NC}"
    fi
}

# Check for encryption settings
check_encryption() {
    echo -e "\n${YELLOW}[*] Checking encryption settings...${NC}"
    
    # This requires Azure CLI and appropriate permissions
    if command -v az &> /dev/null; then
        local encryption_scope=$(az storage account encryption-scope list --account-name "$STORAGE_ACCOUNT" --query "[?status=='Enabled']" -o tsv 2>/dev/null)
        
        if [ -n "$encryption_scope" ]; then
            echo -e "${GREEN}[+] Encryption scopes are configured${NC}"
        else
            echo -e "${YELLOW}[!] No custom encryption scopes found (using default encryption)${NC}"
        fi
        
        # Check for customer-managed keys
        local cmk=$(az storage account show --name "$STORAGE_ACCOUNT" --query 'encryption.keySource' -o tsv 2>/dev/null)
        if [ "$cmk" == "Microsoft.Keyvault" ]; then
            echo -e "${GREEN}[+] Customer-managed keys are being used for encryption${NC}"
        else
            echo -e "${YELLOW}[!] Using Microsoft-managed keys (default)${NC}"
            echo -e "${YELLOW}[*] Consider using customer-managed keys for additional control${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Azure CLI not available for detailed encryption checks${NC}"
    fi
}

# Check for shared access signatures
check_sas_tokens() {
    echo -e "\n${YELLOW}[*] Checking for active SAS tokens...${NC}"
    
    # This is a placeholder - in practice, you'd need to check Azure AD audit logs or storage account settings
    echo -e "${YELLOW}[*] Manual check recommended: Review Azure AD audit logs for SAS token usage${NC}"
    echo -e "${YELLOW}[*] Best practices for SAS tokens:${NC}"
    echo "  - Use short expiration times (hours or days, not months/years)"
    echo "  - Restrict permissions to minimum required"
    echo "  - Use stored access policies when possible"
    echo "  - Monitor and rotate SAS tokens regularly"
}

# Main function
main() {
    # Check for required tools
    check_tools
    
    # Parse command line arguments
    while getopts "a:c:s:o:h" opt; do
        case $opt in
            a) STORAGE_ACCOUNT="$OPTARG" ;;
            c) CONTAINER="$OPTARG" ;;
            s) SAS_TOKEN="$OPTARG" ;;
            o) OUTPUT_FILE="$OPTARG" ;;
            h) usage ;;
            *) usage ;;
        esac
    done
    
    # Validate parameters
    if [ -z "$STORAGE_ACCOUNT" ]; then
        echo -e "${RED}[!] Error: Storage account name is required${NC}"
        usage
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    
    # Redirect output to file and console
    exec > >(tee -a "$OUTPUT_FILE") 2>&1
    
    echo -e "${YELLOW}=== Azure Blob Storage Security Audit ===${NC}"
    echo -e "Storage Account: ${STORAGE_ACCOUNT}"
    if [ -n "$CONTAINER" ]; then
        echo -e "Container: ${CONTAINER}"
    fi
    echo -e "Date: $(date)\n"
    
    # Check if container was provided
    if [ -n "$CONTAINER" ]; then
        check_container_access
        check_sensitive_info
    else
        echo -e "${YELLOW}[*] No container specified. Only account-level checks will be performed.${NC}"
    fi
    
    # Perform account-level checks
    check_cors
    check_network_restrictions
    check_encryption
    check_sas_tokens
    
    echo -e "\n${YELLOW}=== Audit Complete ===${NC}"
    echo -e "Results saved to: ${OUTPUT_FILE}"
}

# Print usage
usage() {
    echo "Usage: $0 -a <storage-account> [-c container] [-s sas-token] [-o output-file]"
    echo "Options:"
    echo "  -a <storage-account>  Name of the Azure Storage Account (required)"
    echo "  -c <container>        Name of the container to check (optional)"
    echo "  -s <sas-token>        SAS token for authentication (optional, will use Azure CLI auth if not provided)"
    echo "  -o <output-file>      Output file (default: azure_blob_audit_<timestamp>.json)"
    echo "  -h                    Show this help message"
    exit 1
}

# Execute main function
main "$@"

exit 0
