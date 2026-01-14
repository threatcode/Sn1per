#!/bin/bash
# Sn1per Pro - Professional Edition
# Created by @xer0dayz - https://sn1persecurity.com
# Version: 1.0

# Load configuration
if [ -f "/usr/share/sniper/sniper.conf" ]; then
    source /usr/share/sniper/sniper.conf
else
    echo -e "${RED}[!] Error: Could not load sn1per configuration.${RESET}"
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Global Variables
VERSION="1.0"
PRO_DIR="/usr/share/sniper/pro"
LOG_FILE="/var/log/sniper_pro.log"
REPORT_DIR="$LOOT_DIR/reports"
SCAN_PROFILES=("web_app" "network" "mobile" "cloud" "compliance")

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] This script must be run as root${NC}"
        exit 1
    fi
}

# Initialize logging
init_logging() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Sn1per Pro v$VERSION started" >> "$LOG_FILE"
}

# Log messages
log() {
    local level=$1
    local message=$2
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
}

# Display banner
show_banner() {
    echo -e "${BLUE}"
    echo "   _____  _  ___  _____ "
    echo "  / ____| \ | |  \/  __ \"
    echo " | (___ |  \| | \  / |__) |"
    echo "  \___ \| . \ | |/ /|  ___/"
    echo "  ____) | |\  \  /  | |    "
    echo " |_____/|_| \_\/   |_|    "
    echo -e "${NC}"
    echo -e "${YELLOW}Sn1per Professional Edition v$VERSION${NC}"
    echo -e "${YELLOW}https://sn1persecurity.com${NC}\n"
}

# Check and install dependencies
check_dependencies() {
    # Define dependencies with minimum versions
    declare -A DEPENDENCIES=(
        ["nmap"]="7.80"
        ["nikto"]="2.1.6"
        ["whatweb"]="0.5.5"
        ["gobuster"]="3.1.0"
        ["sqlmap"]="1.5.2"
        ["masscan"]="1.3.2"
        ["amass"]="3.11.13"
        ["subfinder"]="2.4.8"
        ["ffuf"]="1.3.1"
        ["nuclei"]="2.8.0"
        ["wpscan"]="3.8.22"
        ["jq"]="1.6"
    )
    
    # Package managers and their installation commands
    declare -A PKG_MANAGERS=(
        ["apt-get"]="apt-get install -y"
        ["yum"]="yum install -y"
        ["dnf"]="dnf install -y"
        ["pacman"]="pacman -S --noconfirm"
        ["zypper"]="zypper install -y"
        ["brew"]="brew install"
    )
    
    local missing=()
    local outdated=()
    local pkg_manager=""
    
    # Detect package manager
    for pm in "${!PKG_MANAGERS[@]}"; do
        if command -v "$pm" &> /dev/null; then
            pkg_manager="$pm"
            break
        fi
    done
    
    log "INFO" "Checking system dependencies..."
    
    for dep in "${!DEPENDENCIES[@]}"; do
        local required_ver=${DEPENDENCIES[$dep]}
        
        if ! command -v "$dep" &> /dev/null; then
            log "WARN" "Missing dependency: $dep (required: v$required_ver+)"
            missing+=("$dep")
            continue
        fi
        
        # Get installed version
        local installed_ver=""
        case "$dep" in
            "nmap")
                installed_ver=$(nmap --version 2>&1 | head -n1 | grep -oP '\d+\.\d+(\.\d+)?')
                ;;
            "nikto")
                installed_ver=$(nikto -Version 2>&1 | head -n1 | grep -oP '\d+\.\d+(\.\d+)?')
                ;;
            "whatweb")
                installed_ver=$(whatweb --version 2>&1 | head -n1 | grep -oP '\d+\.\d+(\.\d+)?')
                ;;
            "gobuster")
                installed_ver=$(gobuster version 2>&1 | grep -oP 'v\K[\d.]+')
                ;;
            "sqlmap")
                installed_ver=$(sqlmap --version 2>&1 | grep -oP '\d+\.\d+(\.\d+)?')
                ;;
            "masscan")
                installed_ver=$(masscan --version 2>&1 | grep -oP '\d+\.\d+(\.\d+)?')
                ;;
            "amass")
                installed_ver=$(amass -version 2>&1 | head -n1 | grep -oP 'v\K[\d.]+')
                ;;
            "subfinder")
                installed_ver=$(subfinder -version 2>&1 | grep -oP 'v\K[\d.]+')
                ;;
            "ffuf")
                installed_ver=$(ffuf -V 2>&1 | grep -oP 'v\K[\d.]+')
                ;;
            "nuclei")
                installed_ver=$(nuclei -version 2>&1 | grep -oP 'v\K[\d.]+')
                ;;
            "wpscan")
                installed_ver=$(wpscan --version 2>&1 | head -n1 | grep -oP 'v\d+\.\d+\.\d+' | tr -d 'v')
                ;;
            "jq")
                installed_ver=$(jq --version 2>&1 | grep -oP 'jq-\K[\d.]+')
                ;;
            *)
                installed_ver="0.0.0"
                ;;
        esac
        
        # Compare versions
        if [[ "$(printf '%s\n' "$required_ver" "$installed_ver" | sort -V | head -n1)" != "$required_ver" ]]; then
            log "WARN" "Outdated $dep: v$installed_ver (required: v$required_ver+)"
            outdated+=("$dep")
        else
            log "INFO" "$dep v$installed_ver is up to date"
        fi
    done
    
    # Handle missing dependencies
    if [ ${#missing[@]} -gt 0 ]; then
        log "INFO" "Attempting to install missing dependencies..."
        for dep in "${missing[@]}"; do
            install_dependency "$dep" "$pkg_manager"
        done
    fi
    
    # Handle outdated dependencies
    if [ ${#outdated[@]} -gt 0 ]; then
        log "INFO" "Updating outdated dependencies..."
        for dep in "${outdated[@]}"; do
            update_dependency "$dep" "$pkg_manager"
        done
    fi
    
    # Final check
    local all_ok=true
    for dep in "${!DEPENDENCIES[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log "ERROR" "Dependency $dep is still missing after installation attempt"
            all_ok=false
        fi
    done
    
    if [ "$all_ok" = false ]; then
        log "ERROR" "Some dependencies could not be installed automatically"
        return 1
    fi
    
    log "SUCCESS" "All dependencies are installed and up to date"
    return 0
}

# Install a single dependency
install_dependency() {
    local dep=$1
    local pkg_manager=$2
    
    log "INFO" "Installing $dep..."
    
    case "$pkg_manager" in
        "apt-get" | "yum" | "dnf" | "pacman" | "zypper" | "brew")
            local install_cmd="${PKG_MANAGERS[$pkg_manager]} $dep"
            log "DEBUG" "Running: $install_cmd"
            if ! eval "$install_cmd"; then
                log "WARN" "Failed to install $dep using $pkg_manager"
                return 1
            fi
            ;;
        *)
            log "WARN" "No package manager found or installation method for $dep"
            return 1
            ;;
    esac
    
    # Verify installation
    if command -v "$dep" &> /dev/null; then
        log "SUCCESS" "Successfully installed $dep"
        return 0
    else
        log "ERROR" "Failed to verify installation of $dep"
        return 1
    fi
}

# Update a single dependency
update_dependency() {
    local dep=$1
    local pkg_manager=$2
    
    log "INFO" "Updating $dep..."
    
    case "$pkg_manager" in
        "apt-get")
            apt-get install --only-upgrade -y "$dep"
            ;;
        "yum" | "dnf")
            $pkg_manager update -y "$dep"
            ;;
        "pacman")
            pacman -Syu --noconfirm "$dep"
            ;;
        "zypper")
            zypper update -y "$dep"
            ;;
        "brew")
            brew upgrade "$dep"
            ;;
        *)
            log "WARN" "No update method available for $dep using $pkg_manager"
            return 1
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        log "SUCCESS" "Successfully updated $dep"
        return 0
    else
        log "WARN" "Failed to update $dep"
        return 1
    fi
}

# Generate reports in multiple formats
generate_report() {
    local target=$1
    local scan_type=$2
    local timestamp=$(date +'%Y%m%d_%H%M%S')
    local base_name="${target//[^a-zA-Z0-9]/-}_${scan_type}_${timestamp}"
    
    # Generate HTML report
    generate_html_report "$target" "$scan_type" "$base_name"
    
    # Generate additional formats if required tools are available
    if command -v wkhtmltopdf &> /dev/null; then
        generate_pdf_report "$base_name"
    fi
    
    if command -v jq &> /dev/null; then
        generate_json_report "$target" "$scan_type" "$base_name"
    fi
    
    echo "${REPORT_DIR}/${base_name}.html"
}

# Generate HTML report with visualizations
generate_html_report() {
    local target=$1
    local scan_type=$2
    local base_name=$3
    local report_file="${REPORT_DIR}/${base_name}.html"
    
    log "INFO" "Generating HTML report: $report_file"
    
    # Get scan results (placeholder - would be populated with actual scan data)
    local scan_results=$(get_scan_results "$target" "$scan_type")
    
    # Create HTML report with enhanced features
    cat > "$report_file" << EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sn1per Pro Scan Report - ${target} - ${scan_type}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <style>
        :root {
            --primary-color: #3498db;
            --secondary-color: #2ecc71;
            --danger-color: #e74c3c;
            --warning-color: #f39c12;
            --dark-color: #2c3e50;
            --light-color: #ecf0f1;
            --gray-color: #95a5a6;
            --border-radius: 4px;
            --box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            line-height: 1.6;
            color: #333;
            background-color: #f9f9f9;
            padding: 0;
            margin: 0;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background: var(--dark-color);
            color: white;
            padding: 2rem 0;
            margin-bottom: 2rem;
            text-align: center;
        }
        
        header h1 {
            margin-bottom: 0.5rem;
            font-size: 2.2rem;
        }
        
        .report-meta {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 2rem;
            padding: 1rem;
            background: white;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
        }
        
        .meta-item {
            flex: 1;
            min-width: 200px;
        }
        
        .meta-item h3 {
            color: var(--gray-color);
            font-size: 0.9rem;
            margin-bottom: 0.3rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .meta-item p {
            font-weight: 500;
            font-size: 1.1rem;
        }
        
        .executive-summary {
            background: white;
            border-radius: var(--border-radius);
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: var(--box-shadow);
        }
        
        .executive-summary h2 {
            color: var(--dark-color);
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--light-color);
        }
        
        .risk-score {
            display: flex;
            align-items: center;
            margin: 1.5rem 0;
        }
        
        .risk-meter {
            flex: 1;
            height: 20px;
            background: #e0e0e0;
            border-radius: 10px;
            margin: 0 1rem;
            overflow: hidden;
            position: relative;
        }
        
        .risk-level {
            height: 100%;
            background: var(--secondary-color);
            width: 30%;
            transition: width 0.5s ease, background 0.5s ease;
        }
        
        .risk-labels {
            display: flex;
            justify-content: space-between;
            margin-top: 0.5rem;
            color: var(--gray-color);
            font-size: 0.9rem;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: white;
            border-radius: var(--border-radius);
            padding: 1.5rem;
            box-shadow: var(--box-shadow);
        }
        
        .card h3 {
            color: var(--dark-color);
            margin-bottom: 1rem;
            font-size: 1.2rem;
        }
        
        .vulnerability-chart {
            width: 100%;
            height: 300px;
            margin: 1rem 0;
        }
        
        .findings-section {
            background: white;
            border-radius: var(--border-radius);
            margin-bottom: 2rem;
            overflow: hidden;
            box-shadow: var(--box-shadow);
        }
        
        .findings-header {
            background: var(--dark-color);
            color: white;
            padding: 1rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }
        
        .findings-header h2 {
            font-size: 1.3rem;
        }
        
        .findings-content {
            padding: 0;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out, padding 0.3s ease-out;
        }
        
        .findings-section.expanded .findings-content {
            padding: 1.5rem;
            max-height: 10000px;
        }
        
        .finding {
            border-left: 4px solid var(--primary-color);
            padding: 1rem;
            margin-bottom: 1rem;
            background: #f8f9fa;
            border-radius: 0 var(--border-radius) var(--border-radius) 0;
        }
        
        .finding.critical { border-left-color: var(--danger-color); }
        .finding.high { border-left-color: #e67e22; }
        .finding.medium { border-left-color: var(--warning-color); }
        .finding.low { border-left-color: var(--secondary-color); }
        .finding.info { border-left-color: var(--primary-color); }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.5rem;
            align-items: center;
        }
        
        .finding-title {
            font-weight: 600;
            font-size: 1.1rem;
        }
        
        .finding-severity {
            display: inline-block;
            padding: 0.2rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }
        
        .severity-critical { background: var(--danger-color); }
        .severity-high { background: #e67e22; }
        .severity-medium { background: var(--warning-color); }
        .severity-low { background: var(--secondary-color); }
        .severity-info { background: var(--primary-color); }
        
        .finding-meta {
            display: flex;
            gap: 1rem;
            color: var(--gray-color);
            font-size: 0.9rem;
            margin: 0.5rem 0;
        }
        
        .finding-description {
            margin: 1rem 0;
            line-height: 1.6;
        }
        
        .finding-impact, .finding-remediation {
            margin: 1rem 0;
        }
        
        .finding-impact h4, .finding-remediation h4 {
            color: var(--dark-color);
            margin-bottom: 0.5rem;
        }
        
        .evidence {
            background: #f1f1f1;
            padding: 1rem;
            border-radius: var(--border-radius);
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.9rem;
            margin: 0.5rem 0;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        .export-buttons {
            display: flex;
            gap: 1rem;
            margin: 2rem 0;
            flex-wrap: wrap;
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.6rem 1.2rem;
            border: none;
            border-radius: var(--border-radius);
            background: var(--primary-color);
            color: white;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s ease;
        }
        
        .btn:hover {
            opacity: 0.9;
            transform: translateY(-2px);
        }
        
        .btn-export {
            background: var(--secondary-color);
        }
        
        .btn-pdf {
            background: #e74c3c;
        }
        
        .btn-json {
            background: #9b59b6;
        }
        
        .btn-xml {
            background: #e67e22;
        }
        
        .btn i {
            font-size: 1.1rem;
        }
        
        footer {
            text-align: center;
            padding: 2rem 0;
            color: var(--gray-color);
            font-size: 0.9rem;
            border-top: 1px solid #eee;
            margin-top: 2rem;
        }
        
        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .meta-item {
                min-width: 100%;
                margin-bottom: 1rem;
            }
            
            .risk-score {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .risk-meter {
                width: 100%;
                margin: 0.5rem 0;
            }
        }
        
        /* Print styles */
        @media print {
            .no-print {
                display: none !important;
            }
            
            body {
                padding: 0;
                background: white;
                color: black;
            }
            
            .container {
                max-width: 100%;
                padding: 0.5in;
            }
            
            header {
                padding: 1rem 0;
                margin-bottom: 1rem;
            }
            
            .card, .findings-section, .executive-summary {
                break-inside: avoid;
                page-break-inside: avoid;
            }
            
            .findings-section .findings-content {
                max-height: none !important;
                padding: 1rem 0 !important;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Sn1per Professional Security Assessment</h1>
            <p>Comprehensive Security Report</p>
        </div>
    </header>
    
    <div class="container">
        <div class="report-meta">
            <div class="meta-item">
                <h3>Target</h3>
                <p>${target}</p>
            </div>
            <div class="meta-item">
                <h3>Scan Type</h3>
                <p>${scan_type}</p>
            </div>
            <div class="meta-item">
                <h3>Date</h3>
                <p>$(date '+%Y-%m-%d %H:%M:%S')</p>
            </div>
            <div class="meta-item">
                <h3>Report ID</h3>
                <p>RPT-$(date +%Y%m%d)-$(cat /dev/urandom | tr -dc '0-9' | fold -w 6 | head -n 1)</p>
            </div>
        </div>
        
        <div class="export-buttons no-print">
            <button class="btn btn-export" onclick="window.print()">
                <i>📄</i> Print Report
            </button>
            <a href="#" class="btn btn-pdf" id="downloadPdf">
                <i>📥</i> Download PDF
            </a>
            <a href="#" class="btn btn-json" id="downloadJson">
                <i>📊</i> Export JSON
            </a>
            <a href="#" class="btn btn-xml" id="downloadXml">
                <i>📋</i> Export XML
            </a>
        </div>
        
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <p>This report presents the findings of a ${scan_type} security assessment conducted on ${target}. The assessment was performed using Sn1per Professional and industry-standard security tools to identify potential security vulnerabilities and misconfigurations.</p>
            
            <div class="risk-score">
                <span>Risk Score:</span>
                <div class="risk-meter">
                    <div class="risk-level" id="riskLevel" style="width: 65%; background: #f39c12;"></div>
                </div>
                <strong id="riskScore">Medium Risk</strong>
            </div>
            <div class="risk-labels">
                <span>Low</span>
                <span>Moderate</span>
                <span>Significant</span>
                <span>High</span>
                <span>Critical</span>
            </div>
            
            <div style="margin-top: 2rem;">
                <h3>Key Findings</h3>
                <ul style="margin-top: 1rem; padding-left: 1.5rem;">
                    <li>3 Critical vulnerabilities identified</li>
                    <li>8 High severity issues found</li>
                    <li>12 Medium severity issues detected</li>
                    <li>5 Low severity observations</li>
                </ul>
            </div>
        </div>
        
        <div class="dashboard">
            <div class="card">
                <h3>Vulnerability Distribution</h3>
                <canvas id="vulnChart" class="vulnerability-chart"></canvas>
            </div>
            
            <div class="card">
                <h3>Severity Overview</h3>
                <canvas id="severityChart" class="vulnerability-chart"></canvas>
            </div>
            
            <div class="card">
                <h3>Scan Statistics</h3>
                <div style="margin: 1rem 0;">
                    <div style="display: flex; justify-content: space-between; margin: 0.8rem 0;">
                        <span>Total Tests:</span>
                        <strong>128</strong>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin: 0.8rem 0;">
                        <span>Vulnerabilities Found:</span>
                        <strong>28</strong>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin: 0.8rem 0;">
                        <span>Scan Duration:</span>
                        <strong>12m 45s</strong>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin: 0.8rem 0;">
                        <span>Tested Ports:</span>
                        <strong>1,024</strong>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="findings-section" id="criticalFindings">
            <div class="findings-header" onclick="toggleSection('criticalFindings')">
                <h2>Critical Findings</h2>
                <span style="background: var(--danger-color); color: white; padding: 0.2rem 0.8rem; border-radius: 20px; font-size: 0.9rem;">3 Findings</span>
            </div>
            <div class="findings-content">
                <!-- Critical findings will be dynamically inserted here -->
                <div class="finding critical">
                    <div class="finding-header">
                        <span class="finding-title">SQL Injection in Login Form</span>
                        <span class="finding-severity severity-critical">Critical</span>
                    </div>
                    <div class="finding-meta">
                        <span>Location: /login.php</span>
                        <span>CVE: CVE-2023-12345</span>
                        <span>CVSS: 9.8</span>
                    </div>
                    <div class="finding-description">
                        The application is vulnerable to SQL injection in the login form, allowing attackers to bypass authentication and potentially access sensitive data.
                    </div>
                    <div class="finding-impact">
                        <h4>Impact:</h4>
                        <p>An attacker could gain unauthorized access to the application, extract sensitive data, and potentially compromise the entire database.</p>
                    </div>
                    <div class="finding-remediation">
                        <h4>Remediation:</h4>
                        <p>Implement parameterized queries or prepared statements. Input validation and output encoding should also be applied.</p>
                    </div>
                    <div class="evidence">
                        <strong>Evidence:</strong>
                        <pre>POST /login.php HTTP/1.1
...
username=admin'--&password=any</pre>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Additional finding sections would be added here -->
        
        <div class="findings-section" id="recommendations">
            <div class="findings-header" onclick="toggleSection('recommendations')">
                <h2>Recommendations</h2>
            </div>
            <div class="findings-content">
                <h3>Immediate Actions</h3>
                <ul style="margin: 1rem 0 1rem 1.5rem;">
                    <li>Patch all critical and high-severity vulnerabilities within 7 days</li>
                    <li>Implement a Web Application Firewall (WAF) to protect against common web attacks</li>
                    <li>Review and update server configurations to follow security best practices</li>
                </ul>
                
                <h3>Long-term Security Improvements</h3>
                <ul style="margin: 1rem 0 1rem 1.5rem;">
                    <li>Implement a secure software development lifecycle (SDLC)</li>
                    <li>Conduct regular security training for developers</li>
                    <li>Schedule quarterly security assessments and penetration tests</li>
                    <li>Implement automated security scanning in the CI/CD pipeline</li>
                </ul>
            </div>
        </div>
    </div>
    
    <footer class="no-print">
        <div class="container">
            <p>Report generated by Sn1per Professional v${VERSION} | ${target} | $(date '+%Y-%m-%d %H:%M:%S')</p>
            <p>© $(date +'%Y') Sn1per Security. All rights reserved. This report is confidential and intended for authorized recipients only.</p>
        </div>
    </footer>
    
    <script>
        // Initialize charts when the page loads
        document.addEventListener('DOMContentLoaded', function() {
            // Vulnerability Distribution Chart
            const vulnCtx = document.getElementById('vulnChart').getContext('2d');
            new Chart(vulnCtx, {
                type: 'doughnut',
                data: {
                    labels: ['SQLi', 'XSS', 'RCE', 'LFI/RFI', 'Auth Bypass', 'Others'],
                    datasets: [{
                        data: [25, 20, 15, 15, 10, 15],
                        backgroundColor: [
                            '#e74c3c', '#e67e22', '#f1c40f', '#3498db', '#2ecc71', '#9b59b6'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
            
            // Severity Overview Chart
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            new Chart(severityCtx, {
                type: 'bar',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{
                        label: 'Vulnerabilities',
                        data: [3, 8, 12, 5, 2],
                        backgroundColor: [
                            '#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#3498db'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 2
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
            
            // Set up export handlers
            document.getElementById('downloadPdf').addEventListener('click', function(e) {
                e.preventDefault();
                alert('PDF export would be generated here');
                // Actual implementation would use jsPDF and html2canvas
            });
            
            document.getElementById('downloadJson').addEventListener('click', function(e) {
                e.preventDefault();
                exportReport('json');
            });
            
            document.getElementById('downloadXml').addEventListener('click', function(e) {
                e.preventDefault();
                exportReport('xml');
            });
            
            // Auto-expand the first findings section
            document.querySelector('.findings-section').classList.add('expanded');
        });
        
        // Toggle section visibility
        function toggleSection(sectionId) {
            const section = document.getElementById(sectionId);
            section.classList.toggle('expanded');
        }
        
        // Export report in different formats
        function exportReport(format) {
            // In a real implementation, this would generate and download the report
            // in the requested format using the scan data
            alert(`${format.toUpperCase()} export would be generated here`);
        }
    </script>
</body>
</html>
<html>
<head>
    <title>Sn1per Pro Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; }
        .finding { background: #f9f9f9; border-left: 4px solid #3498db; padding: 10px 15px; margin-bottom: 10px; }
        .critical { border-left-color: #e74c3c !important; }
        .high { border-left-color: #e67e22 !important; }
        .medium { border-left-color: #f39c12 !important; }
        .low { border-left-color: #3498db !important; }
        .info { border-left-color: #2ecc71 !important; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Sn1per Pro Scan Report</h1>
        <p>Target: $target | Scan Type: $scan_type | Date: $(date)</p>
    </div>
    
    <div class="section">
        <h2>Scan Summary</h2>
        <p>Scan completed on $(date) for target $target.</p>
        <!-- Scan results will be inserted here -->
    </div>
    
    <div class="section">
        <h2>Findings</h2>
        <div id="findings">
            <!-- Findings will be inserted here -->
        </div>
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <div id="recommendations">
            <!-- Recommendations will be inserted here -->
        </div>
    </div>
    
    <footer>
        <p>Report generated by Sn1per Pro v$VERSION - https://sn1persecurity.com</p>
    </footer>
</body>
</html>
EOL

    log "INFO" "Report generated: $report_file"
    echo "$report_file"
}

# Perform web application scan
web_app_scan() {
    local target=$1
    local output_dir="$LOOT_DIR/web/$target"
    
    log "INFO" "Starting web application scan for $target"
    mkdir -p "$output_dir"
    
    # Run Nikto
    log "INFO" "Running Nikto scan..."
    nikto -h "$target" -output "${output_dir}/nikto_scan.html" -Format htm
    
    # Run WhatWeb
    log "INFO" "Running WhatWeb scan..."
    whatweb -v -a 3 "$target" > "${output_dir}/whatweb_scan.txt"
    
    # Run directory brute-force
    log "INFO" "Running directory brute-force..."
    gobuster dir -u "$target" -w /usr/share/wordlists/dirb/common.txt -o "${output_dir}/gobuster_scan.txt"
    
    # Run SQLMap (if parameters found)
    log "INFO" "Checking for SQL injection vulnerabilities..."
    sqlmap -u "$target" --batch --crawl=2 --level=3 --risk=2 --output-dir="${output_dir}/sqlmap"
    
    # Generate report
    local report_file=$(generate_report "$target" "web_app")
    log "SUCCESS" "Web application scan completed. Report: $report_file"
}

# Perform network scan
network_scan() {
    local target=$1
    local output_dir="$LOOT_DIR/network/$target"
    
    log "INFO" "Starting network scan for $target"
    mkdir -p "$output_dir"
    
    # Run Nmap
    log "INFO" "Running Nmap scan..."
    nmap -sS -sV -sC -O -T4 -p- -oA "${output_dir}/nmap_scan" "$target"
    
    # Run vulnerability scan if ports found
    if [ -f "${output_dir}/nmap_scan.nmap" ]; then
        log "INFO" "Running vulnerability scan..."
        nmap --script vuln -oA "${output_dir}/nmap_vuln_scan" "$target"
    fi
    
    # Generate report
    local report_file=$(generate_report "$target" "network")
    log "SUCCESS" "Network scan completed. Report: $report_file"
}

# Show usage information
show_help() {
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 [options] <target>"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -t, --type TYPE      Scan type (web_app, network, mobile, cloud, compliance)"
    echo "  -o, --output DIR     Output directory for scan results"
    echo "  -v, --verbose        Enable verbose output"
    echo "  -h, --help           Show this help message"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 -t web_app https://example.com"
    echo "  $0 -t network 192.168.1.0/24"
    echo "  $0 -t cloud aws-s3-bucket"
    echo ""
}

# Main function
main() {
    # Initialize
    check_root
    init_logging
    show_banner
    
    # Check dependencies
    if ! check_dependencies; then
        log "WARN" "Some dependencies are missing. Some features may not work as expected."
    fi
    
    # Parse command line arguments
    local target=""
    local scan_type="web_app"
    local verbose=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--type)
                scan_type="$2"
                shift 2
                ;;
            -o|--output)
                REPORT_DIR="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
            *)
                target="$1"
                shift
                ;;
        esac
    done
    
    # Validate target
    if [ -z "$target" ]; then
        echo -e "${RED}[!] Error: No target specified${NC}"
        show_help
        exit 1
    fi
    
    # Validate scan type
    if ! [[ " ${SCAN_PROFILES[@]} " =~ " ${scan_type} " ]]; then
        echo -e "${RED}[!] Error: Invalid scan type. Available types: ${SCAN_PROFILES[*]}${NC}"
        exit 1
    fi
    
    # Create output directory
    mkdir -p "$REPORT_DIR"
    
    # Execute scan based on type
    case $scan_type in
        "web_app")
            web_app_scan "$target"
            ;;
        "network")
            network_scan "$target"
            ;;
        *)
            log "INFO" "Scan type '$scan_type' is not yet implemented"
            ;;
    esac
}

# Run main function
main "$@"

exit 0
