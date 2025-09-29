#!/bin/bash
# Kubernetes API Security Checker
# Description: Checks for common Kubernetes API misconfigurations and security issues
# Author: Sn1per
# Version: 1.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default values
KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}
CONTEXT=""
NAMESPACE="default"
OUTPUT_FILE="k8s_audit_$(date +%Y%m%d_%H%M%S).json"

# Check if kubectl is installed and configured
check_kubectl() {
    if ! command -v kubectl &> /dev/null; then
        echo -e "${RED}[!] Error: kubectl is not installed${NC}"
        echo "Install it with: https://kubernetes.io/docs/tasks/tools/"
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${RED}[!] Error: Could not connect to Kubernetes cluster${NC}"
        echo "Make sure your kubeconfig is properly configured"
        exit 1
    fi
}

# Check if required tools are installed
check_tools() {
    local missing=0
    for tool in jq; do
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

# Check Kubernetes version
check_version() {
    echo -e "\n${YELLOW}[*] Checking Kubernetes version...${NC}"
    
    local version=$(kubectl version --output=json 2>/dev/null | jq -r '.serverVersion.gitVersion')
    local major=$(echo $version | cut -d'v' -f2 | cut -d'.' -f1)
    local minor=$(echo $version | cut -d'.' -f2)
    
    echo "Cluster version: $version"
    
    # Check if version is too old
    if [ $major -lt 1 ] || { [ $major -eq 1 ] && [ $minor -lt 18 ]; }; then
        echo -e "${RED}[!] WARNING: Outdated Kubernetes version (v${major}.${minor}) with known vulnerabilities${NC}"
    fi
}

# Check anonymous authentication
check_anonymous_auth() {
    echo -e "\n${YELLOW}[*] Checking anonymous authentication...${NC}"
    
    local endpoints=(
        "/api"
        "/api/v1"
        "/apis"
        "/healthz"
        "/version"
    )
    
    local vulnerable=0
    
    for endpoint in "${endpoints[@]}"; do
        local url="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}${endpoint}"
        local response=$(curl -sk -o /dev/null -w "%{http_code}" "$url")
        
        if [ "$response" == "200" ] || [ "$response" == "403" ]; then
            echo -e "${RED}[!] WARNING: Anonymous access enabled at ${endpoint} (HTTP ${response})${NC}"
            vulnerable=1
        fi
    done
    
    if [ $vulnerable -eq 0 ]; then
        echo -e "${GREEN}[+] Anonymous authentication is disabled or properly restricted${NC}"
    fi
}

# Check for insecure ports
check_insecure_ports() {
    echo -e "\n${YELLOW}[*] Checking for insecure ports...${NC}"
    
    local ports=(
        "8080"  # Insecure API server port
        "10250" # Kubelet API
        "10255" # Read-only Kubelet API
        "10256" # Kube Proxy
        "4194"  # cAdvisor
    )
    
    local vulnerable=0
    
    for port in "${ports[@]}"; do
        if nc -zv -w 1 $KUBERNETES_SERVICE_HOST $port &> /dev/null; then
            echo -e "${RED}[!] WARNING: Insecure port ${port} is open${NC}"
            vulnerable=1
        fi
    done
    
    if [ $vulnerable -eq 0 ]; then
        echo -e "${GREEN}[+] No insecure ports detected${NC}"
    fi
}

# Check RBAC configuration
check_rbac() {
    echo -e "\n${YELLOW}[*] Checking RBAC configuration...${NC}"
    
    # Check if RBAC is enabled
    local rbac_enabled=$(kubectl api-versions | grep -c rbac.authorization.k8s.io/v1)
    
    if [ $rbac_enabled -eq 0 ]; then
        echo -e "${RED}[!] WARNING: RBAC is not enabled${NC}"
        return
    fi
    
    echo -e "${GREEN}[+] RBAC is enabled${NC}"
    
    # Check for overly permissive roles
    local permissive_roles=$(kubectl get clusterroles --no-headers | awk '{print $1}' | xargs -I {} sh -c "kubectl get clusterrole {} -o json | jq -r 'select(.rules[]?.verbs[]? | contains(\"*\")) | .metadata.name'" 2>/dev/null)
    
    if [ -n "$permissive_roles" ]; then
        echo -e "${YELLOW}[!] WARNING: The following roles have wildcard permissions:${NC}"
        echo "$permissive_roles" | sed 's/^/  - /'
    else
        echo -e "${GREEN}[+] No overly permissive roles found${NC}"
    fi
    
    # Check for default service account tokens
    local default_tokens=$(kubectl get serviceaccount default -o jsonpath='{.secrets[0].name}' 2>/dev/null)
    
    if [ -n "$default_tokens" ]; then
        echo -e "${YELLOW}[!] WARNING: Default service account has a token mounted${NC}"
        echo -e "${YELLOW}[*] Consider setting 'automountServiceAccountToken: false' for the default service account${NC}"
    fi
}

# Check network policies
check_network_policies() {
    echo -e "\n${YELLOW}[*] Checking network policies...${NC}"
    
    local policies=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l)
    
    if [ $policies -eq 0 ]; then
        echo -e "${YELLOW}[!] WARNING: No network policies found${NC}"
        echo -e "${YELLOW}[*] Consider implementing network policies to restrict pod-to-pod traffic${NC}"
    else
        echo -e "${GREEN}[+] ${policies} network policies found${NC}"
    fi
}

# Check for exposed dashboards
check_exposed_dashboards() {
    echo -e "\n${YELLOW}[*] Checking for exposed dashboards...${NC}"
    
    local dashboards=(
        "kubernetes-dashboard"
        "kube-dashboard"
        "weave-scope"
        "tiller"
        "kibana"
        "grafana"
        "prometheus"
    )
    
    local found=0
    
    for dashboard in "${dashboards[@]}"; do
        local svcs=$(kubectl get svc --all-namespaces -o json | jq -r ".items[] | select(.metadata.name | contains(\"$dashboard\")) | \"\(.metadata.namespace)/\(.metadata.name)\"" 2>/dev/null)
        
        for svc in $svcs; do
            local ns=$(echo $svc | cut -d'/' -f1)
            local name=$(echo $svc | cut -d'/' -f2)
            local type=$(kubectl -n $ns get svc $name -o jsonpath='{.spec.type}' 2>/dev/null)
            
            if [ "$type" == "LoadBalancer" ] || [ "$type" == "NodePort" ]; then
                echo -e "${RED}[!] WARNING: Exposed dashboard found: ${ns}/${name} (Type: ${type})${NC}"
                found=1
            fi
        done
    done
    
    if [ $found -eq 0 ]; then
        echo -e "${GREEN}[+] No exposed dashboards found${NC}"
    fi
}

# Check for privileged containers
check_privileged_containers() {
    echo -e "\n${YELLOW}[*] Checking for privileged containers...${NC}"
    
    local privileged=$(kubectl get pods --all-namespaces -o jsonpath='{.items[?(@.spec.containers[].securityContext.privileged==true)].metadata.name}' 2>/dev/null)
    
    if [ -n "$privileged" ]; then
        echo -e "${RED}[!] WARNING: The following pods are running with privileged mode:${NC}"
        echo "$privileged" | tr ' ' '\n' | sed 's/^/  - /'
    else
        echo -e "${GREEN}[+] No privileged containers found${NC}"
    fi
}

# Check for host network access
check_host_network() {
    echo -e "\n${YELLOW}[*] Checking for pods using host network...${NC}"
    
    local host_network=$(kubectl get pods --all-namespaces -o jsonpath='{.items[?(@.spec.hostNetwork==true)].metadata.name}' 2>/dev/null)
    
    if [ -n "$host_network" ]; then
        echo -e "${YELLOW}[!] WARNING: The following pods are using host network:${NC}"
        echo "$host_network" | tr ' ' '\n' | sed 's/^/  - /'
    else
        echo -e "${GREEN}[+] No pods using host network found${NC}"
    fi
}

# Check for default service accounts
check_default_service_accounts() {
    echo -e "\n${YELLOW}[*] Checking for default service accounts...${NC}"
    
    local default_sas=$(kubectl get serviceaccounts --all-namespaces -o json | jq -r '.items[] | select(.metadata.name=="default" and (.automountServiceAccountToken==true or .automountServiceAccountToken==null)) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null)
    
    if [ -n "$default_sas" ]; then
        echo -e "${YELLOW}[!] WARNING: The following namespaces have default service accounts with auto-mounted tokens:${NC}"
        echo "$default_sas" | sed 's/^/  - /'
        echo -e "${YELLOW}[*] Consider creating dedicated service accounts with least privileges${NC}"
    else
        echo -e "${GREEN}[+] No default service accounts with auto-mounted tokens found${NC}"
    fi
}

# Check for exposed secrets
check_exposed_secrets() {
    echo -e "\n${YELLOW}[*] Checking for exposed secrets...${NC}"
    
    local secrets=$(kubectl get secrets --all-namespaces --field-selector type=Opaque -o json 2>/dev/null)
    
    if [ -n "$secrets" ]; then
        local secret_count=$(echo "$secrets" | jq -r '.items | length' 2>/dev/null)
        echo -e "${YELLOW}[*] Found ${secret_count} Opaque secrets${NC}"
        
        # Check for secrets with sensitive data
        local sensitive_secrets=$(echo "$secrets" | jq -r '.items[] | select(.data) | .metadata as $m | .data | to_entries[] | select(.key | test("(password|secret|token|key|credential|api[_-]?key|access[_-]?key|auth|private|confidential)", "i")) | "\($m.namespace)/\($m.name)/\(.key)"' 2>/dev/null)
        
        if [ -n "$sensitive_secrets" ]; then
            echo -e "${YELLOW}[!] WARNING: The following secrets may contain sensitive data:${NC}"
            echo "$sensitive_secrets" | sed 's/^/  - /'
            echo -e "${YELLOW}[*] Ensure these secrets are properly secured and not exposed in environment variables${NC}"
        fi
    else
        echo -e "${YELLOW}[-] Could not retrieve secrets (insufficient permissions)${NC}"
    fi
}

# Main function
main() {
    # Check for required tools
    check_kubectl
    check_tools
    
    # Set context if provided
    if [ -n "$CONTEXT" ]; then
        kubectl config use-context "$CONTEXT"
        if [ $? -ne 0 ]; then
            echo -e "${RED}[!] Error: Could not switch to context '$CONTEXT'${NC}"
            exit 1
        fi
    fi
    
    # Set namespace if provided
    if [ -n "$NAMESPACE" ]; then
        kubectl config set-context --current --namespace="$NAMESPACE"
        if [ $? -ne 0 ]; then
            echo -e "${YELLOW}[!] Warning: Could not set namespace to '$NAMESPACE'${NC}"
        fi
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    
    # Redirect output to file and console
    exec > >(tee -a "$OUTPUT_FILE") 2>&1
    
    echo -e "${YELLOW}=== Kubernetes API Security Audit ===${NC}"
    echo -e "Context: $(kubectl config current-context 2>/dev/null || echo "default")"
    echo -e "Namespace: ${NAMESPACE}"
    echo -e "Date: $(date)\n"
    
    # Run all checks
    check_version
    check_anonymous_auth
    check_insecure_ports
    check_rbac
    check_network_policies
    check_exposed_dashboards
    check_privileged_containers
    check_host_network
    check_default_service_accounts
    check_exposed_secrets
    
    echo -e "\n${YELLOW}=== Audit Complete ===${NC}"
    echo -e "Results saved to: ${OUTPUT_FILE}"
}

# Print usage
usage() {
    echo "Usage: $0 [-c context] [-n namespace] [-o output-file]"
    echo "Options:"
    echo "  -c <context>      Kubernetes context to use (default: current context)"
    echo "  -n <namespace>    Namespace to check (default: default)"
    echo "  -o <output-file>  Output file (default: k8s_audit_<timestamp>.json)"
    echo "  -h                Show this help message"
    exit 1
}

# Parse command line arguments
while getopts "c:n:o:h" opt; do
    case $opt in
        c) CONTEXT="$OPTARG" ;;
        n) NAMESPACE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Execute main function
main

exit 0
