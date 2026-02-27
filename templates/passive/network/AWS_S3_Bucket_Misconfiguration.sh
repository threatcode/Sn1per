#!/bin/bash
# AWS S3 Bucket Misconfiguration Checker
# Description: Checks for common S3 bucket misconfigurations including public access, CORS, and ACL issues
# Author: Sn1per
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default values
BUCKET_NAME=""
REGION="us-east-1"
OUTPUT_FILE="s3_audit_$(date +%Y%m%d_%H%M%S).txt"

# Check if AWS CLI is installed
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}[!] Error: AWS CLI is not installed${NC}"
        echo "Install it with: pip3 install awscli"
        exit 1
    fi
    
    # Check AWS configuration
    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}[!] Error: AWS CLI not configured or invalid credentials${NC}"
        echo "Run 'aws configure' to set up your AWS credentials"
        exit 1
    fi
}

# Check if bucket exists
check_bucket_exists() {
    if aws s3 ls "s3://$BUCKET_NAME" --region "$REGION" &> /dev/null; then
        return 0
    else
        echo -e "${RED}[!] Error: Bucket $BUCKET_NAME does not exist or you don't have permission to access it${NC}"
        return 1
    fi
}

# Check bucket ACLs
check_bucket_acl() {
    echo -e "\n${YELLOW}[*] Checking bucket ACLs...${NC}"
    acl_result=$(aws s3api get-bucket-acl --bucket "$BUCKET_NAME" --region "$REGION" 2>&1)
    
    if echo "$acl_result" | grep -q '"Permission": "READ"'; then
        echo -e "${RED}[!] WARNING: Public READ access detected in bucket ACL${NC}"
        echo "$acl_result" | jq .
    else
        echo -e "${GREEN}[+] No public READ access in bucket ACL${NC}"
    fi
}

# Check bucket policy
check_bucket_policy() {
    echo -e "\n${YELLOW}[*] Checking bucket policy...${NC}"
    policy_result=$(aws s3api get-bucket-policy --bucket "$BUCKET_NAME" --region "$REGION" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        echo -e "${YELLOW}[*] Bucket policy found. Checking for insecure configurations...${NC}"
        echo "$policy_result" | jq .
        
        # Check for wildcards in Principal
        if echo "$policy_result" | grep -q '\"*\"'; then
            echo -e "${RED}[!] WARNING: Wildcard (*) found in Principal field of bucket policy${NC}"
        fi
        
        # Check for insecure actions
        if echo "$policy_result" | grep -qE 's3:GetObject|s3:ListBucket|s3:GetBucketLocation|s3:GetObjectVersion' | grep -v 'Deny'; then
            echo -e "${YELLOW}[!] Potentially permissive actions found in bucket policy${NC}"
        fi
    else
        echo -e "${GREEN}[+] No bucket policy found (this is generally good unless default ACLs are permissive)${NC}"
    fi
}

# Check bucket public access block
check_public_access_block() {
    echo -e "\n${YELLOW}[*] Checking public access block settings...${NC}"
    public_access_block=$(aws s3api get-public-access-block --bucket "$BUCKET_NAME" --region "$REGION" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        echo "$public_access_block" | jq .
        
        block_public_acls=$(echo "$public_access_block" | jq -r '.BlockPublicAcls')
        ignore_public_acls=$(echo "$public_access_block" | jq -r '.IgnorePublicAcls')
        block_public_policy=$(echo "$public_access_block" | jq -r '.BlockPublicPolicy')
        restrict_public_buckets=$(echo "$public_access_block" | jq -r '.RestrictPublicBuckets')
        
        if [[ $block_public_acls == "false" || $ignore_public_acls == "false" || 
              $block_public_policy == "false" || $restrict_public_buckets == "false" ]]; then
            echo -e "${YELLOW}[!] WARNING: Some public access settings are not fully restricted${NC}"
        else
            echo -e "${GREEN}[+] Public access is fully blocked for this bucket${NC}"
        fi
    else
        echo -e "${RED}[!] WARNING: Unable to retrieve public access block settings${NC}"
    fi
}

# Check bucket versioning
check_versioning() {
    echo -e "\n${YELLOW}[*] Checking versioning status...${NC}"
    versioning=$(aws s3api get-bucket-versioning --bucket "$BUCKET_NAME" --region "$REGION" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        echo "$versioning" | jq .
        if echo "$versioning" | grep -q '"Status": "Enabled"'; then
            echo -e "${GREEN}[+] Versioning is enabled${NC}"
        else
            echo -e "${YELLOW}[!] Versioning is not enabled. Consider enabling it for data protection.${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Unable to retrieve versioning status${NC}"
    fi
}

# Check server-side encryption
check_encryption() {
    echo -e "\n${YELLOW}[*] Checking server-side encryption...${NC}"
    encryption=$(aws s3api get-bucket-encryption --bucket "$BUCKET_NAME" --region "$REGION" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        echo "$encryption" | jq .
        echo -e "${GREEN}[+] Server-side encryption is enabled${NC}"
    else
        echo -e "${RED}[!] WARNING: Server-side encryption is not enabled${NC}"
    fi
}

# Check bucket logging
check_logging() {
    echo -e "\n${YELLOW}[*] Checking logging configuration...${NC}"
    logging=$(aws s3api get-bucket-logging --bucket "$BUCKET_NAME" --region "$REGION" 2>&1)
    
    if [[ $? -eq 0 && -n $(echo "$logging" | jq '.LoggingEnabled') ]]; then
        echo "$logging" | jq .
        echo -e "${GREEN}[+] Server access logging is enabled${NC}"
    else
        echo -e "${YELLOW}[!] WARNING: Server access logging is not enabled${NC}"
    fi
}

# Check for website configuration
check_website_config() {
    echo -e "\n${YELLOW}[*] Checking for static website configuration...${NC}"
    website=$(aws s3api get-bucket-website --bucket "$BUCKET_NAME" --region "$REGION" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        echo "$website" | jq .
        echo -e "${YELLOW}[!] WARNING: Static website hosting is enabled${NC}"
    else
        echo -e "${GREEN}[+] No static website configuration found${NC}"
    fi
}

# Check CORS configuration
check_cors() {
    echo -e "\n${YELLOW}[*] Checking CORS configuration...${NC}"
    cors=$(aws s3api get-bucket-cors --bucket "$BUCKET_NAME" --region "$REGION" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        echo "$cors" | jq .
        
        # Check for permissive CORS
        if echo "$cors" | grep -q '\"*\"'; then
            echo -e "${RED}[!] WARNING: Permissive CORS configuration detected (AllOrigins: *)${NC}"
        fi
        
        # Check for insecure methods
        if echo "$cors" | grep -qE 'PUT|POST|DELETE'; then
            echo -e "${YELLOW}[!] WARNING: Potentially dangerous HTTP methods allowed in CORS configuration${NC}"
        fi
    else
        echo -e "${GREEN}[+] No CORS configuration found${NC}"
    fi
}

# Main function
main() {
    # Check for required tools
    check_aws_cli
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}[!] Error: jq is required but not installed${NC}"
        echo "Install it with: brew install jq (macOS) or apt-get install jq (Linux)"
        exit 1
    fi
    
    # Parse command line arguments
    while getopts "b:r:o:h" opt; do
        case $opt in
            b) BUCKET_NAME="$OPTARG" ;;
            r) REGION="$OPTARG" ;;
            o) OUTPUT_FILE="$OPTARG" ;;
            h) usage ;;
            *) usage ;;
        esac
    done
    
    # Validate parameters
    if [ -z "$BUCKET_NAME" ]; then
        echo -e "${RED}[!] Error: Bucket name is required${NC}"
        usage
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    
    # Redirect all output to file and console
    exec > >(tee -a "$OUTPUT_FILE") 2>&1
    
    echo -e "\n${YELLOW}=== S3 Bucket Security Audit ===${NC}"
    echo -e "Bucket: ${BUCKET_NAME}"
    echo -e "Region: ${REGION}"
    echo -e "Date: $(date)\n"
    
    # Check if bucket exists
    if ! check_bucket_exists; then
        exit 1
    fi
    
    # Run all checks
    check_bucket_acl
    check_bucket_policy
    check_public_access_block
    check_versioning
    check_encryption
    check_logging
    check_website_config
    check_cors
    
    echo -e "\n${YELLOW}=== Audit Complete ===${NC}"
    echo -e "Results saved to: ${OUTPUT_FILE}"
}

# Print usage
usage() {
    echo "Usage: $0 -b <bucket-name> [-r region] [-o output-file]"
    echo "Options:"
    echo "  -b <bucket-name>  Name of the S3 bucket to audit (required)"
    echo "  -r <region>       AWS region (default: us-east-1)"
    echo "  -o <output-file>  Output file (default: s3_audit_<timestamp>.txt)"
    echo "  -h                Show this help message"
    exit 1
}

# Execute main function
main "$@"

exit 0
