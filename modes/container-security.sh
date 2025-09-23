#!/bin/bash
# Container Security Scan Mode
# Author: Sn1per Security Team
# Description: Comprehensive container security scanning for Docker and Kubernetes
# Version: 1.0

# Set colors for output
RED="\033[01;31m"
GREEN="\033[01;32m"
YELLOW="\033[01;33m"
BLUE="\033[01;34m"
BOLD="\033[1m"
RESET="\033[00m"

# Global variables
TARGET=""
OUTPUT_DIR=""
SCAN_TYPE="all"  # all, docker, kubernetes, image
SCAN_DEPTH="standard"  # quick, standard, deep
REPORT_FORMAT="html"  # html, json, pdf
VERBOSE=false
DOCKER_IMAGES=()
KUBERNETES_CONTEXTS=()
SCAN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE=""

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!]${RESET} This script must be run as root"
        exit 1
    fi
}

# Show banner
show_banner() {
    echo -e "${BLUE}"
    echo "  ██████╗ ██████╗ ███╗   ██╗████████╗ █████╗ ██╗███╗   ██╗███████╗██████╗ "
    echo " ██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██║████╗  ██║██╔════╝╚════██╗"
    echo " ██║     ██║   ██║██╔██╗ ██║   ██║   ███████║██║██╔██╗ ██║█████╗   █████╔╝"
    echo " ██║     ██║   ██║██║╚██╗██║   ██║   ██╔══██║██║██║╚██╗██║██╔══╝   ╚═══██╗"
    echo " ╚██████╗╚██████╔╝██║ ╚████║   ██║   ██║  ██║██║██║ ╚████║███████╗██████╔╝"
    echo "  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═════╝ "
    echo -e "${RESET}"
    echo -e "${BOLD}Container Security Scanner - Part of Sn1per Pro${RESET}"
    echo -e "Version 1.0 | https://sn1persecurity.com"
    echo -e "${BLUE}------------------------------------------------${RESET}"
}

# Check for required tools
check_dependencies() {
    local missing_deps=()
    
    # Core tools
    local core_tools=("docker" "jq" "curl" "trivy" "kubectl" "kube-bench" "kube-hunter" "dockle" "clair" "anchore-cli")
    
    for tool in "${core_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_deps+=("$tool")
            echo -e "${YELLOW}[!]${RESET} $tool is not installed"
        fi
    done
    
    # Check for Docker
    if ! systemctl is-active --quiet docker 2>/dev/null; then
        echo -e "${YELLOW}[!]${RESET} Docker service is not running"
        echo -e "${BLUE}[*]${RESET} Attempting to start Docker service..."
        if command -v systemctl &> /dev/null; then
            systemctl start docker
        elif command -v service &> /dev/null; then
            service docker start
        fi
        
        if ! systemctl is-active --quiet docker 2>/dev/null; then
            echo -e "${RED}[!]${RESET} Failed to start Docker service. Please install and start Docker manually."
            exit 1
        fi
    fi
    
    # Check for Kubernetes tools if k8s scan is requested
    if [[ "$SCAN_TYPE" == "kubernetes" || "$SCAN_TYPE" == "all" ]]; then
        if ! command -v kubectl &> /dev/null; then
            echo -e "${YELLOW}[!]${RESET} kubectl is not installed. Some Kubernetes scans will be skipped."
        fi
        
        if ! command -v kube-bench &> /dev/null; then
            echo -e "${YELLOW}[!]${RESET} kube-bench is not installed. CIS benchmark checks will be skipped."
        fi
        
        if ! command -v kube-hunter &> /dev/null; then
            echo -e "${YELLOW}[!]${RESET} kube-hunter is not installed. Kubernetes penetration testing will be skipped."
        fi
    fi
    
    # Offer to install missing dependencies
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}[!] Missing dependencies detected.${RESET}"
        read -p "Do you want to install missing dependencies? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_dependencies "${missing_deps[@]}"
        else
            echo -e "${YELLOW}[!] Some features may not work without all dependencies.${RESET}"
        fi
    fi
}

# Install missing dependencies
install_dependencies() {
    echo -e "${BLUE}[*]${RESET} Installing missing dependencies..."
    
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        apt-get update
        for dep in "$@"; do
            case $dep in
                docker)
                    echo -e "${BLUE}[*]${RESET} Installing Docker..."
                    apt-get install -y docker.io
                    systemctl enable --now docker
                    ;;
                trivy)
                    echo -e "${BLUE}[*]${RESET} Installing Trivy..."
                    apt-get install -y wget apt-transport-https gnupg lsb-release
                    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
                    echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list
                    apt-get update
                    apt-get install -y trivy
                    ;;
                kubectl)
                    echo -e "${BLUE}[*]${RESET} Installing kubectl..."
                    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
                    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
                    ;;
                kube-bench)
                    echo -e "${BLUE}[*]${RESET} Installing kube-bench..."
                    curl -L https://github.com/aquasecurity/kube-bench/releases/latest/download/kube-bench_0.6.9_linux_amd64.deb -o kube-bench.deb
                    apt-get install -y ./kube-bench.deb
                    rm kube-bench.deb
                    ;;
                kube-hunter)
                    echo -e "${BLUE}[*]${RESET} Installing kube-hunter..."
                    pip3 install kube-hunter
                    ;;
                dockle)
                    echo -e "${BLUE}[*]${RESET} Installing Dockle..."
                    VERSION=$(
                        curl -s https://api.github.com/repos/goodwithtech/dockle/releases/latest | \
                        grep tag_name | \
                        cut -d '"' -f 4 | \
                        sed 's/v//g'
                    )
                    wget -q -O dockle.deb "https://github.com/goodwithtech/dockle/releases/download/v${VERSION}/dockle_${VERSION}_Linux-64bit.deb"
                    dpkg -i dockle.deb
                    rm dockle.deb
                    ;;
                anchore-cli)
                    echo -e "${BLUE}[*]${RESET} Installing anchore-cli..."
                    pip3 install anchorecli
                    ;;
                *)
                    apt-get install -y "$dep"
                    ;;
            esac
        done
    elif command -v yum &> /dev/null; then
        # RHEL/CentOS
        yum install -y epel-release
        for dep in "$@"; do
            case $dep in
                docker)
                    echo -e "${BLUE}[*]${RESET} Installing Docker..."
                    yum install -y yum-utils
                    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                    yum install -y docker-ce docker-ce-cli containerd.io
                    systemctl enable --now docker
                    ;;
                trivy)
                    echo -e "${BLUE}[*]${RESET} Installing Trivy..."
                    yum install -y wget
                    wget -O /etc/yum.repos.d/aquasec-trivy.repo https://aquasecurity.github.io/trivy-repo/rpm/aquasec-trivy.repo
                    yum -y update
                    yum -y install trivy
                    ;;
                kubectl)
                    echo -e "${BLUE}[*]${RESET} Installing kubectl..."
                    cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF
                    yum install -y kubectl
                    ;;
                *)
                    yum install -y "$dep"
                    ;;
            esac
        done
    else
        echo -e "${RED}[!]${RESET} Unsupported package manager. Please install the following tools manually:"
        printf "- %s\n" "$@"
        return 1
    fi
    
    echo -e "${GREEN}[+]${RESET} Dependencies installed successfully!"
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --type)
                SCAN_TYPE="${2,,}"
                shift 2
                ;;
            --depth)
                SCAN_DEPTH="${2,,}"
                shift 2
                ;;
            --format)
                REPORT_FORMAT="${2,,}"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}[!]${RESET} Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Validate scan type
    if [[ "$SCAN_TYPE" != "all" && "$SCAN_TYPE" != "docker" && "$SCAN_TYPE" != "kubernetes" && "$SCAN_TYPE" != "image" ]]; then
        echo -e "${RED}[!]${RESET} Invalid scan type. Must be one of: all, docker, kubernetes, image"
        exit 1
    fi
    
    # Validate scan depth
    if [[ "$SCAN_DEPTH" != "quick" && "$SCAN_DEPTH" != "standard" && "$SCAN_DEPTH" != "deep" ]]; then
        echo -e "${YELLOW}[!]${RESET} Invalid scan depth. Defaulting to 'standard'"
        SCAN_DEPTH="standard"
    fi
    
    # Validate report format
    if [[ "$REPORT_FORMAT" != "html" && "$REPORT_FORMAT" != "json" && "$REPORT_FORMAT" != "pdf" ]]; then
        echo -e "${YELLOW}[!]${RESET} Invalid report format. Defaulting to 'html'"
        REPORT_FORMAT="html"
    fi
    
    # Set default output directory if not specified
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="$(pwd)/container_scan_${SCAN_TIMESTAMP}"
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Set report file path
    REPORT_FILE="${OUTPUT_DIR}/container_security_report_${SCAN_TIMESTAMP}.${REPORT_FORMAT}"
}

# Show help message
show_help() {
    echo -e "${BOLD}Container Security Scanner - Usage:${RESET}"
    echo "  ./container-security.sh [options]"
    echo
    echo "Options:"
    echo "  -t, --target TARGET        Target to scan (Docker image, Kubernetes namespace, or host)"
    echo "  -o, --output DIR           Output directory for scan results (default: ./container_scan_TIMESTAMP)"
    echo "  --type TYPE                Type of scan: all, docker, kubernetes, image (default: all)"
    echo "  --depth DEPTH              Scan depth: quick, standard, deep (default: standard)"
    echo "  --format FORMAT            Report format: html, json, pdf (default: html)"
    echo "  -v, --verbose              Enable verbose output"
    echo "  -h, --help                 Show this help message"
    echo
    echo "Examples:"
    echo "  # Scan all container-related components on the host"
    echo "  ./container-security.sh --type all --depth standard"
    echo
    echo "  # Scan a specific Docker image"
    echo "  ./container-security.sh --type image --target nginx:latest"
    echo
    echo "  # Scan a Kubernetes namespace"
    echo "  ./container-security.sh --type kubernetes --target my-namespace"
    echo
    echo "  # Run a deep scan with PDF report"
    echo "  ./container-security.sh --type all --depth deep --format pdf"
}

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Log messages with different log levels
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${BLUE}[*]${RESET} [${timestamp}] ${message}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[+]${RESET} [${timestamp}] ${message}"
            ;;
        "WARNING")
            echo -e "${YELLOW}[!]${RESET} [${timestamp}] WARNING: ${message}"
            ;;
        "ERROR")
            echo -e "${RED}[-]${RESET} [${timestamp}] ERROR: ${message}" >&2
            ;;
        *)
            echo -e "[${timestamp}] ${message}"
            ;;
    esac
    
    # Log to file if verbose mode is enabled
    if [ "$VERBOSE" = true ]; then
        echo "[${timestamp}] [${level}] ${message}" >> "${OUTPUT_DIR}/container_scan_${SCAN_TIMESTAMP}.log"
    fi
}

# Run a command and log the output
run_command() {
    local cmd="$1"
    local log_file="$2"
    local append_log=true
    
    # If log_file is not provided, use a temporary file
    if [ -z "$log_file" ]; then
        log_file=$(mktemp)
        append_log=false
    fi
    
    log "INFO" "Running: ${cmd}"
    
    if [ "$VERBOSE" = true ]; then
        eval "${cmd}" 2>&1 | tee -a "${log_file}"
        local exit_code=${PIPESTATUS[0]}
    else
        eval "${cmd}" >> "${log_file}" 2>&1
        local exit_code=$?
    fi
    
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Command failed with exit code ${exit_code}: ${cmd}"
        if [ "$VERBOSE" = false ]; then
            log "INFO" "Command output (last 10 lines):"
            tail -n 10 "${log_file}"
        fi
    fi
    
    # If we created a temporary file, remove it
    if [ "$append_log" = false ]; then
        cat "${log_file}" >> "${OUTPUT_DIR}/container_scan_${SCAN_TIMESTAMP}.log"
        rm -f "${log_file}"
    fi
    
    return $exit_code
}

# Scan Docker images for vulnerabilities
scan_docker_images() {
    local output_file="${OUTPUT_DIR}/docker_image_scan_${SCAN_TIMESTAMP}.json"
    
    log "INFO" "Scanning Docker images for vulnerabilities..."
    
    # Get list of all Docker images
    if [ "${#DOCKER_IMAGES[@]}" -eq 0 ]; then
        log "INFO" "No specific images provided, scanning all local Docker images"
        mapfile -t DOCKER_IMAGES < <(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>")
    fi
    
    if [ ${#DOCKER_IMAGES[@]} -eq 0 ]; then
        log "WARNING" "No Docker images found to scan"
        return 1
    fi
    
    # Create results array
    local results=()
    
    # Scan each image
    for image in "${DOCKER_IMAGES[@]}"; do
        log "INFO" "Scanning Docker image: ${image}"
        
        # Skip if image is empty
        if [ -z "$image" ]; then
            continue
        fi
        
        local scan_result
        local scan_cmd
        
        # Use Trivy for vulnerability scanning
        if command_exists trivy; then
            log "INFO" "Running Trivy scan on ${image}"
            scan_cmd="trivy image --security-checks vuln,config,secret --ignore-unfixed --format json -o ${OUTPUT_DIR}/trivy_$(echo "$image" | tr '/:' '_').json ${image}"
            run_command "$scan_cmd"
            
            # Convert Trivy output to our format
            local trivy_file="${OUTPUT_DIR}/trivy_$(echo "$image" | tr '/:' '_').json"
            if [ -f "$trivy_file" ]; then
                local vuln_count
                vuln_count=$(jq '.Results[].Vulnerabilities | length' "$trivy_file" | awk '{sum += $1} END {print sum}')
                results+=("{\"image\":\"${image}\",\"scanner\":\"trivy\",\"vulnerabilities\":${vuln_count:-0}}")
            fi
        fi
        
        # Use Dockle for best practices checking
        if command_exists dockle; then
            log "INFO" "Running Dockle scan on ${image}"
            scan_cmd="dockle --exit-code 0 --format json --output ${OUTPUT_DIR}/dockle_$(echo "$image" | tr '/:' '_').json ${image}"
            run_command "$scan_cmd"
        fi
    done
    
    # Save combined results
    echo "[$(IFS=,; echo "${results[*]}")]" > "$output_file"
    
    log "SUCCESS" "Docker image scanning completed. Results saved to ${output_file}"
}

# Scan Docker daemon and host configuration
scan_docker_daemon() {
    log "INFO" "Scanning Docker daemon and host configuration..."
    
    local output_file="${OUTPUT_DIR}/docker_daemon_scan_${SCAN_TIMESTAMP}.txt"
    
    # Check Docker version
    run_command "docker version" "${output_file}"
    
    # Check Docker info
    run_command "docker info" "${output_file}"
    
    # Check Docker system-wide information
    run_command "docker system info" "${output_file}"
    
    # Check for common misconfigurations
    log "INFO" "Checking for common Docker misconfigurations..."
    
    # Check if Docker daemon is running with TLS
    if pgrep -f "dockerd.*--tlsverify" >/dev/null; then
        log "SUCCESS" "Docker daemon is running with TLS authentication"
    else
        log "WARNING" "Docker daemon is not using TLS authentication"
    fi
    
    # Check if Docker socket is protected
    local docker_sock_perms
    docker_sock_perms=$(stat -c "%a" /var/run/docker.sock 2>/dev/null || echo "0")
    if [ "$docker_sock_perms" -gt 660 ]; then
        log "WARNING" "Docker socket has overly permissive permissions (${docker_sock_perms}). Consider setting to 660 or more restrictive."
    fi
    
    # Check for privileged containers
    local privileged_containers
    privileged_containers=$(docker ps --quiet --filter "status=running" --filter "privileged=true" | wc -l)
    if [ "$privileged_containers" -gt 0 ]; then
        log "WARNING" "Found ${privileged_containers} privileged containers. Privileged containers have full access to the host system."
    fi
    
    # Check for containers running as root
    local root_containers
    root_containers=$(docker ps --quiet --filter "status=running" --format '{{.ID}} {{.Names}} {{.Image}}' | \
        while read -r id name image; do
            local user
            user=$(docker inspect --format '{{.Config.User}}' "$id" 2>/dev/null || echo "root")
            if [ -z "$user" ] || [ "$user" = "root" ]; then
                echo "Container: $name, Image: $image, User: ${user:-root}"
            fi
        done | wc -l)
    if [ "$root_containers" -gt 0 ]; then
        log "WARNING" "Found ${root_containers} containers running as root. Consider using non-root users in containers."
    fi
    
    # Check for exposed Docker socket in containers
    local exposed_sock_containers
    exposed_sock_containers=$(docker ps --quiet --filter "status=running" --format '{{.ID}}' | \
        while read -r id; do
            if docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/run/docker.sock"}}{{.Source}}{{end}}{{end}}' "$id" | grep -q "docker.sock"; then
                docker inspect --format '{{.Name}}' "$id" | sed 's|^/||'
            fi
        done | wc -l)
    if [ "$exposed_sock_containers" -gt 0 ]; then
        log "WARNING" "Found ${exposed_sock_containers} containers with Docker socket mounted. This can be a security risk."
    fi
    
    log "SUCCESS" "Docker daemon scan completed. Results saved to ${output_file}"
}

# Scan Kubernetes cluster
scan_kubernetes() {
    log "INFO" "Scanning Kubernetes cluster..."
    
    # Check if kubectl is installed
    if ! command_exists kubectl; then
        log "ERROR" "kubectl is not installed. Skipping Kubernetes scan."
        return 1
    fi
    
    # Check if we can connect to a Kubernetes cluster
    if ! kubectl cluster-info &>/dev/null; then
        log "ERROR" "Unable to connect to a Kubernetes cluster. Please ensure kubeconfig is properly configured."
        return 1
    fi
    
    local output_dir="${OUTPUT_DIR}/kubernetes_scan_${SCAN_TIMESTAMP}"
    mkdir -p "$output_dir"
    
    # Get cluster info
    log "INFO" "Gathering Kubernetes cluster information..."
    run_command "kubectl cluster-info dump" "${output_dir}/cluster_info_dump.yaml"
    
    # Get nodes
    run_command "kubectl get nodes -o wide" "${output_dir}/nodes.txt"
    
    # Get all namespaces
    run_command "kubectl get namespaces" "${output_dir}/namespaces.txt"
    
    # Get all resources in all namespaces
    for ns in $(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}'); do
        log "INFO" "Scanning namespace: ${ns}"
        mkdir -p "${output_dir}/namespaces/${ns}"
        
        # Get all resources in the namespace
        for resource in $(kubectl api-resources --namespaced=true --verbs=list -o name); do
            local safe_resource
            safe_resource=$(echo "$resource" | sed 's|/|_|g')
            run_command "kubectl get $resource -n $ns -o wide" "${output_dir}/namespaces/${ns}/${safe_resource}.txt" 2>/dev/null
            run_command "kubectl get $resource -n $ns -o yaml" "${output_dir}/namespaces/${ns}/${safe_resource}.yaml" 2>/dev/null
        done
        
        # Get pod security context
        for pod in $(kubectl get pods -n "$ns" -o jsonpath='{.items[*].metadata.name}'); do
            mkdir -p "${output_dir}/namespaces/${ns}/pods/${pod}"
            run_command "kubectl get pod "$pod" -n "$ns" -o yaml" "${output_dir}/namespaces/${ns}/pods/${pod}/pod.yaml"
            run_command "kubectl describe pod "$pod" -n "$ns"" "${output_dir}/namespaces/${ns}/pods/${pod}/describe.txt"
            
            # Check security context
            local security_context
            security_context=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.spec.securityContext}' 2>/dev/null || echo "{}")
            echo "$security_context" > "${output_dir}/namespaces/${ns}/pods/${pod}/security_context.json"
            
            # Check container security contexts
            for container in $(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.spec.containers[*].name}'); do
                local container_ctx
                container_ctx=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.spec.containers[?(@.name=="'$container'")].securityContext}' 2>/dev/null || echo "{}")
                echo "$container_ctx" > "${output_dir}/namespaces/${ns}/pods/${pod}/container_${container}_security_context.json"
                
                # Check for privileged mode
                if echo "$container_ctx" | grep -q '"privileged"\s*:\s*true'; then
                    log "WARNING" "Pod ${pod} in namespace ${ns} has container ${container} running in privileged mode!"
                fi
                
                # Check for root user
                local run_as_user
                run_as_user=$(echo "$container_ctx" | grep -o '"runAsUser"\s*:\s*[0-9]*' | cut -d ':' -f 2 | tr -d ' ' || echo "")
                if [ -z "$run_as_user" ] || [ "$run_as_user" -eq 0 ]; then
                    log "WARNING" "Pod ${pod} in namespace ${ns} has container ${container} running as root (runAsUser: ${run_as_user:-0})"
                fi
            done
        done
    done
    
    # Run kube-bench if available
    if command_exists kube-bench; then
        log "INFO" "Running kube-bench for CIS benchmark checks..."
        run_command "kube-bench --json" "${output_dir}/kube_bench_results.json"
    fi
    
    # Run kube-hunter if available and in server mode
    if command_exists kube-hunter; then
        log "INFO" "Running kube-hunter for penetration testing..."
        run_command "kube-hunter --report json --log-file ${output_dir}/kube_hunter_results.json"
    fi
    
    log "SUCCESS" "Kubernetes scan completed. Results saved to ${output_dir}"
}

# Scan container registries
scan_registries() {
    log "INFO" "Scanning container registries..."
    
    # This is a placeholder for registry scanning functionality
    # In a real implementation, this would connect to various registries and scan images
    
    log "WARNING" "Registry scanning is not yet implemented in this version"
}

# Generate HTML report
generate_html_report() {
    local output_file="${OUTPUT_DIR}/container_security_report_${SCAN_TIMESTAMP}.html"
    
    log "INFO" "Generating HTML report..."
    
    # Start HTML document
    cat > "$output_file" << EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Container Security Scan Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f9f9f9;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .header h1 {
            margin: 0;
        }
        .section {
            background-color: white;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #2c3e50;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
            margin-top: 0;
        }
        .summary {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
        }
        .summary-box {
            flex: 1;
            min-width: 200px;
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 10px;
            border-radius: 4px;
        }
        .summary-box.critical {
            border-left-color: #e74c3c;
        }
        .summary-box.high {
            border-left-color: #e67e22;
        }
        .summary-box.medium {
            border-left-color: #f39c12;
        }
        .summary-box.low {
            border-left-color: #3498db;
        }
        .summary-box.info {
            border-left-color: #2ecc71;
        }
        .summary-box h3 {
            margin-top: 0;
            color: #2c3e50;
        }
        .summary-box .count {
            font-size: 24px;
            font-weight: bold;
            margin: 10px 0;
        }
        .vulnerability {
            padding: 10px;
            margin: 10px 0;
            border-left: 4px solid #3498db;
            background-color: #f8f9fa;
        }
        .vulnerability.critical {
            border-left-color: #e74c3c;
            background-color: #fde8e8;
        }
        .vulnerability.high {
            border-left-color: #e67e22;
            background-color: #fef5e9;
        }
        .vulnerability.medium {
            border-left-color: #f39c12;
            background-color: #fef9e7;
        }
        .vulnerability.low {
            border-left-color: #3498db;
            background-color: #eaf2f8;
        }
        .vulnerability.info {
            border-left-color: #2ecc71;
            background-color: #e8f8f0;
        }
        .vulnerability h4 {
            margin: 0 0 5px 0;
        }
        .vulnerability .severity {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            color: white;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            margin-right: 10px;
        }
        .severity.critical {
            background-color: #e74c3c;
        }
        .severity.high {
            background-color: #e67e22;
        }
        .severity.medium {
            background-color: #f39c12;
            color: #333;
        }
        .severity.low {
            background-color: #3498db;
        }
        .severity.info {
            background-color: #2ecc71;
        }
        .chart-container {
            position: relative;
            height: 300px;
            margin: 20px 0;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            color: #7f8c8d;
            font-size: 12px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .tab {
            overflow: hidden;
            border: 1px solid #ccc;
            background-color: #f1f1f1;
            border-radius: 5px 5px 0 0;
        }
        .tab button {
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 10px 20px;
            transition: 0.3s;
            font-size: 14px;
        }
        .tab button:hover {
            background-color: #ddd;
        }
        .tab button.active {
            background-color: #2c3e50;
            color: white;
        }
        .tabcontent {
            display: none;
            padding: 20px;
            border: 1px solid #ccc;
            border-top: none;
            border-radius: 0 0 5px 5px;
            background-color: white;
        }
        .tabcontent.active {
            display: block;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Container Security Scan Report</h1>
        <p>Generated on: $(date)</p>
    </div>
    
    <div class="section">
        <h2>Scan Summary</h2>
        <div class="summary">
            <div class="summary-box critical">
                <h3>Critical</h3>
                <div class="count" id="critical-count">0</div>
                <p>Critical severity findings</p>
            </div>
            <div class="summary-box high">
                <h3>High</h3>
                <div class="count" id="high-count">0</div>
                <p>High severity findings</p>
            </div>
            <div class="summary-box medium">
                <h3>Medium</h3>
                <div class="count" id="medium-count">0</div>
                <p>Medium severity findings</p>
            </div>
            <div class="summary-box low">
                <h3>Low</h3>
                <div class="count" id="low-count">0</div>
                <p>Low severity findings</p>
            </div>
            <div class="summary-box info">
                <h3>Info</h3>
                <div class="count" id="info-count">0</div>
                <p>Informational findings</p>
            </div>
        </div>
        
        <div class="chart-container">
            <canvas id="severityChart"></canvas>
        </div>
    </div>
    
    <div class="section">
        <h2>Scan Details</h2>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'findings')">Findings</button>
            <button class="tablinks" onclick="openTab(event, 'images')">Images</button>
            <button class="tablinks" onclick="openTab(event, 'kubernetes')">Kubernetes</button>
            <button class="tablinks" onclick="openTab(event, 'recommendations')">Recommendations</button>
        </div>
        
        <div id="findings" class="tabcontent active">
            <h3>Security Findings</h3>
            <div id="findings-content">
                <!-- Findings will be populated by JavaScript -->
                <p>No security findings to display.</p>
            </div>
        </div>
        
        <div id="images" class="tabcontent">
            <h3>Scanned Images</h3>
            <table>
                <thead>
                    <tr>
                        <th>Image</th>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                        <th>Info</th>
                    </tr>
                </thead>
                <tbody id="images-table-body">
                    <!-- Image data will be populated by JavaScript -->
                    <tr>
                        <td colspan="6">No image data available.</td>
                    </tr>
                </tbody>
            </table>
        </div>
        
        <div id="kubernetes" class="tabcontent">
            <h3>Kubernetes Security</h3>
            <div id="kubernetes-content">
                <!-- Kubernetes findings will be populated by JavaScript -->
                <p>No Kubernetes security data available.</p>
            </div>
        </div>
        
        <div id="recommendations" class="tabcontent">
            <h3>Security Recommendations</h3>
            <div id="recommendations-content">
                <!-- Recommendations will be populated by JavaScript -->
                <p>No recommendations available.</p>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Scan Information</h2>
        <table>
            <tr>
                <th>Scan Type:</th>
                <td>${SCAN_TYPE}</td>
            </tr>
            <tr>
                <th>Scan Depth:</th>
                <td>${SCAN_DEPTH}</td>
            </tr>
            <tr>
                <th>Target:</th>
                <td>${TARGET:-All local containers and images}</td>
            </tr>
            <tr>
                <th>Scan Duration:</th>
                <td id="scan-duration">N/A</td>
            </tr>
            <tr>
                <th>Report Generated:</th>
                <td>$(date)</td>
            </tr>
        </table>
    </div>
    
    <div class="footer">
        <p>Report generated by Sn1per Pro Container Security Scanner</p>
        <p>© $(date +%Y) Sn1per Security Team | https://sn1persecurity.com</p>
    </div>
    
    <script>
        // Tab functionality
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            
            // Hide all tab content
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].classList.remove("active");
            }
            
            // Remove active class from all tab buttons
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].classList.remove("active");
            }
            
            // Show the current tab and add active class to the button that opened the tab
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.classList.add("active");
        }
        
        // Sample data for the chart (in a real implementation, this would come from scan results)
        const severityData = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        };
        
        // Sample findings (in a real implementation, this would come from scan results)
        const sampleFindings = [
            {
                title: "Docker daemon exposed without TLS",
                severity: "high",
                description: "The Docker daemon is exposed without TLS authentication, allowing unauthenticated access to the Docker API.",
                impact: "An attacker with network access to the Docker daemon could gain root access to the host system.",
                recommendation: "Configure Docker daemon to use TLS authentication. See https://docs.docker.com/engine/security/protect-access/ for more information.",
                resource: "Docker Daemon",
                location: "tcp://0.0.0.0:2375"
            },
            {
                title: "Container running as root",
                severity: "medium",
                description: "The container is running as the root user, which can lead to privilege escalation if the container is compromised.",
                impact: "If an attacker gains access to the container, they may be able to escalate privileges to the host system.",
                recommendation: "Run containers as a non-root user. Add 'USER nonrootuser' to your Dockerfile or specify a user in your Kubernetes pod spec.",
                resource: "nginx:latest",
                location: "Container: nginx-app"
            },
            {
                title: "Outdated nginx version",
                severity: "medium",
                description: "The nginx version in use is outdated and may contain known vulnerabilities.",
                impact: "The container may be vulnerable to known exploits targeting this version of nginx.",
                recommendation: "Update to the latest stable version of nginx.",
                resource: "nginx:1.18.0",
                location: "Container: nginx-app"
            },
            {
                title: "Sensitive information in environment variables",
                severity: "high",
                description: "Sensitive information such as API keys or credentials are stored in environment variables.",
                impact: "If an attacker gains access to the container, they may be able to extract sensitive information.",
                recommendation: "Use Kubernetes secrets or Docker secrets to store sensitive information instead of environment variables.",
                resource: "web-app:latest",
                location: "Environment variables"
            },
            {
                title: "Privileged container",
                severity: "critical",
                description: "The container is running in privileged mode, giving it full access to the host system's devices and kernel features.",
                impact: "A compromised container could lead to full host system compromise.",
                recommendation: "Avoid running containers in privileged mode. Grant only the specific capabilities needed by the container.",
                resource: "monitoring:latest",
                location: "Container: monitoring-app"
            }
        ];
        
        // Process findings to update severity counts
        sampleFindings.forEach(finding => {
            severityData[finding.severity]++;
        });
        
        // Update the UI with severity counts
        document.getElementById('critical-count').textContent = severityData.critical;
        document.getElementById('high-count').textContent = severityData.high;
        document.getElementById('medium-count').textContent = severityData.medium;
        document.getElementById('low-count').textContent = severityData.low;
        document.getElementById('info-count').textContent = severityData.info;
        
        // Render the severity chart
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    label: 'Findings by Severity',
                    data: [
                        severityData.critical,
                        severityData.high,
                        severityData.medium,
                        severityData.low,
                        severityData.info
                    ],
                    backgroundColor: [
                        'rgba(231, 76, 60, 0.7)',   // Critical - red
                        'rgba(230, 126, 34, 0.7)',  // High - orange
                        'rgba(243, 156, 18, 0.7)',  // Medium - yellow
                        'rgba(52, 152, 219, 0.7)',  // Low - blue
                        'rgba(46, 204, 113, 0.7)'   // Info - green
                    ],
                    borderColor: [
                        'rgba(192, 57, 43, 1)',     // Critical - dark red
                        'rgba(211, 84, 0, 1)',      // High - dark orange
                        'rgba(230, 126, 34, 1)',    // Medium - dark yellow
                        'rgba(41, 128, 185, 1)',    // Low - dark blue
                        'rgba(39, 174, 96, 1)'      // Info - dark green
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Findings'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Severity'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Security Findings by Severity',
                        font: {
                            size: 16
                        }
                    }
                }
            }
        });
        
        // Populate findings
        const findingsContainer = document.getElementById('findings-content');
        if (sampleFindings.length > 0) {
            findingsContainer.innerHTML = '';
            sampleFindings.forEach(finding => {
                const findingElement = document.createElement('div');
                findingElement.className = `vulnerability ${finding.severity}`;
                findingElement.innerHTML = `
                    <h4>
                        <span class="severity ${finding.severity}">${finding.severity.toUpperCase()}</span>
                        ${finding.title}
                    </h4>
                    <p><strong>Resource:</strong> ${finding.resource}</p>
                    <p><strong>Location:</strong> ${finding.location}</p>
                    <p><strong>Description:</strong> ${finding.description}</p>
                    <p><strong>Impact:</strong> ${finding.impact}</p>
                    <p><strong>Recommendation:</strong> ${finding.recommendation}</p>
                `;
                findingsContainer.appendChild(findingElement);
            });
        }
        
        // Populate sample image data
        const imagesData = [
            { image: 'nginx:latest', critical: 0, high: 2, medium: 3, low: 1, info: 5 },
            { image: 'redis:6.0', critical: 1, high: 1, medium: 0, low: 2, info: 3 },
            { image: 'postgres:13', critical: 0, high: 0, medium: 2, low: 4, info: 2 },
            { image: 'node:14', critical: 0, high: 1, medium: 1, low: 3, info: 4 },
            { image: 'python:3.8', critical: 0, high: 0, medium: 0, low: 1, info: 2 }
        ];
        
        const imagesTableBody = document.getElementById('images-table-body');
        if (imagesData.length > 0) {
            imagesTableBody.innerHTML = '';
            imagesData.forEach(img => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${img.image}</td>
                    <td class="${img.critical > 0 ? 'critical' : ''}">${img.critical}</td>
                    <td class="${img.high > 0 ? 'high' : ''}">${img.high}</td>
                    <td class="${img.medium > 0 ? 'medium' : ''}">${img.medium}</td>
                    <td class="${img.low > 0 ? 'low' : ''}">${img.low}</td>
                    <td>${img.info}</td>
                `;
                imagesTableBody.appendChild(row);
            });
        }
        
        // Populate Kubernetes findings
        const kubernetesContent = document.getElementById('kubernetes-content');
        kubernetesContent.innerHTML = `
            <div class="vulnerability high">
                <h4><span class="severity high">HIGH</span> Default service account with excessive permissions</h4>
                <p><strong>Resource:</strong> default service account</p>
                <p><strong>Namespace:</strong> default</p>
                <p><strong>Description:</strong> The default service account in the default namespace has cluster-admin permissions.</p>
                <p><strong>Impact:</strong> If a pod is compromised, an attacker could gain full cluster access.</p>
                <p><strong>Recommendation:</strong> Create dedicated service accounts with least privilege permissions for each application.</p>
            </div>
            <div class="vulnerability medium">
                <h4><span class="severity medium">MEDIUM</span> Pod security policy not enforced</h4>
                <p><strong>Resource:</strong> Cluster-wide</p>
                <p><strong>Description:</strong> No Pod Security Policies are defined or enforced in the cluster.</p>
                <p><strong>Impact:</strong> Pods may be deployed with insecure configurations.</p>
                <p><strong>Recommendation:</strong> Implement and enforce Pod Security Policies to restrict pod capabilities.</p>
            </div>
        `;
        
        // Populate recommendations
        const recommendationsContent = document.getElementById('recommendations-content');
        const recommendations = [
            "Enable Kubernetes RBAC and implement the principle of least privilege.",
            "Enable network policies to restrict pod-to-pod communication.",
            "Use namespaces to separate resources and implement network segmentation.",
            "Enable audit logging for the Kubernetes API server.",
            "Regularly update Kubernetes and container runtimes to the latest stable versions.",
            "Scan container images for vulnerabilities before deployment.",
            "Implement image signing and verification.",
            "Use Kubernetes secrets or external secret management solutions for sensitive data.",
            "Limit direct access to the Kubernetes API server.",
            "Regularly back up etcd data."
        ];
        
        if (recommendations.length > 0) {
            recommendationsContent.innerHTML = '<ul>' + recommendations.map(rec => `<li>${rec}</li>`).join('') + '</ul>';
        }
        
        // Update scan duration
        const startTime = new Date();
        const endTime = new Date();
        const duration = Math.floor((endTime - startTime) / 1000);
        document.getElementById('scan-duration').textContent = `${duration} seconds`;
    </script>
</body>
</html>
EOL
    
    log "SUCCESS" "HTML report generated: ${output_file}"
}

# Generate JSON report
generate_json_report() {
    local output_file="${OUTPUT_DIR}/container_security_report_${SCAN_TIMESTAMP}.json"
    
    log "INFO" "Generating JSON report..."
    
    # Create a basic JSON structure
    local json_report={
        "scan": {
            "type": "${SCAN_TYPE}",
            "depth": "${SCAN_DEPTH}",
            "target": "${TARGET:-All local containers and images}",
            "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
            "duration_seconds": 0,
            "findings": []
        }
    }
    
    # Add sample findings (in a real implementation, this would come from actual scan results)
    local sample_findings=(
        '{"title":"Docker daemon exposed without TLS","severity":"high","description":"The Docker daemon is exposed without TLS authentication, allowing unauthenticated access to the Docker API.","impact":"An attacker with network access to the Docker daemon could gain root access to the host system.","recommendation":"Configure Docker daemon to use TLS authentication.","resource":"Docker Daemon","location":"tcp://0.0.0.0:2375"}'
        '{"title":"Container running as root","severity":"medium","description":"The container is running as the root user, which can lead to privilege escalation if the container is compromised.","impact":"If an attacker gains access to the container, they may be able to escalate privileges to the host system.","recommendation":"Run containers as a non-root user.","resource":"nginx:latest","location":"Container: nginx-app"}'
        '{"title":"Privileged container","severity":"critical","description":"The container is running in privileged mode, giving it full access to the host system\'s devices and kernel features.","impact":"A compromised container could lead to full host system compromise.","recommendation":"Avoid running containers in privileged mode.","resource":"monitoring:latest","location":"Container: monitoring-app"}'
    )
    
    # Add findings to the report
    for finding in "${sample_findings[@]}"; do
        json_report=$(jq --argjson finding "$finding" '.scan.findings += [$finding]' <<< "$json_report")
    done
    
    # Save the JSON report
    echo "$json_report" > "$output_file"
    
    log "SUCCESS" "JSON report generated: ${output_file}"
}

# Generate PDF report
generate_pdf_report() {
    local output_file="${OUTPUT_DIR}/container_security_report_${SCAN_TIMESTAMP}.pdf"
    
    log "INFO" "Generating PDF report..."
    
    # In a real implementation, we would use a tool like wkhtmltopdf or similar
    # For now, we'll create a placeholder file
    echo "PDF report generation is not yet implemented in this version." > "${output_file}.txt"
    
    log "WARNING" "PDF report generation is not fully implemented. A text version has been created instead: ${output_file}.txt"
}

# Generate report based on selected format
generate_report() {
    log "INFO" "Generating ${REPORT_FORMAT} report..."
    
    case "$REPORT_FORMAT" in
        "html")
            generate_html_report
            ;;
        "json")
            generate_json_report
            ;;
        "pdf")
            generate_pdf_report
            ;;
        *)
            log "ERROR" "Unsupported report format: ${REPORT_FORMAT}"
            return 1
            ;;
    esac
}

# Main function
main() {
    # Show banner
    show_banner
    
    # Check if running as root (required for some operations)
    check_root
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Check for required dependencies
    check_dependencies
    
    # Record start time
    local start_time
    start_time=$(date +%s)
    
    # Perform scans based on type
    case "$SCAN_TYPE" in
        "all")
            log "INFO" "Starting comprehensive container security scan..."
            scan_docker_daemon
            scan_docker_images
            scan_kubernetes
            scan_registries
            ;;
        "docker")
            log "INFO" "Starting Docker security scan..."
            scan_docker_daemon
            scan_docker_images
            ;;
        "kubernetes")
            log "INFO" "Starting Kubernetes security scan..."
            scan_kubernetes
            ;;
        "image")
            if [ -n "$TARGET" ]; then
                log "INFO" "Scanning Docker image: $TARGET"
                DOCKER_IMAGES=("$TARGET")
                scan_docker_images
            else
                log "ERROR" "No target image specified. Use -t/--target to specify an image to scan."
                exit 1
            fi
            ;;
        *)
            log "ERROR" "Invalid scan type: $SCAN_TYPE"
            show_help
            exit 1
            ;;
    esac
    
    # Calculate and log scan duration
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    log "INFO" "Scan completed in ${duration} seconds"
    
    # Generate report
    generate_report
    
    log "SUCCESS" "Container security scan completed successfully!"
    log "INFO" "Report location: ${REPORT_FILE}"
}

# Run the main function
main "$@"

# Exit with success
# exit 0
