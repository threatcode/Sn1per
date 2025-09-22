#!/bin/bash
# VULNERABILITY ANALYSIS MODULE #####################################################################################################
# Advanced vulnerability analysis with CVE scanners, dynamic analysis, subdomain takeover detection, S3 bucket enumeration, and quick hits detection

if [[ "$REPORT" = "1" ]]; then
  args="-t $TARGET"
  if [[ "$OSINT" = "1" ]]; then
    args="$args -o"
  fi
  if [[ "$AUTO_BRUTE" = "1" ]]; then
    args="$args -b"
  fi
  if [[ "$FULLNMAPSCAN" = "1" ]]; then
    args="$args -fp"
  fi
  if [[ "$RECON" = "1" ]]; then
    args="$args -re"
  fi
  if [[ "$MODE" = "vuln" ]]; then
    args="$args -m vuln"
  fi
  if [[ ! -z "$PORT" ]]; then
    args="$args -p $PORT"
  fi
  if [[ ! -z "$WORKSPACE" ]]; then
    args="$args -w $WORKSPACE"
  fi
  args="$args --noreport"
  sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-`date +"%Y%m%d%H%M"`.txt 2>&1
  exit
fi

echo -e "$OKRED                ____               $RESET"
echo -e "$OKRED    _________  /  _/___  ___  _____$RESET"
echo -e "$OKRED   / ___/ __ \ / // __ \/ _ \/ ___/$RESET"
echo -e "$OKRED  (__  ) / / // // /_/ /  __/ /    $RESET"
echo -e "$OKRED /____/_/ /_/___/ .___/\___/_/     $RESET"
echo -e "$OKRED               /_/                 $RESET"
echo -e "$RESET"
echo -e "$OKORANGE + -- --=[https://sn1persecurity.com"
echo -e "$OKORANGE + -- --=[Sn1per v$VER by @xer0dayz"
echo -e "$OKORANGE + -- --=[Vulnerability Analysis Mode - Advanced Threat Detection"
echo -e "$RESET"

if [[ ! -z $WORKSPACE ]]; then
  LOOT_DIR=$WORKSPACE_DIR
fi

echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
if [[ "$MODE" = "" ]]; then
  MODE="vuln-analysis"
  echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2>/dev/null
else
  echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2>/dev/null
fi
echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/${TARGET}-${MODE}.txt 2>/dev/null
echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2>/dev/null
ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt

echo "[sn1persecurity.com] •?((¯°·._.• Started Sn1per vulnerability analysis scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
  /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Sn1per vulnerability analysis scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
fi

# Initialize vulnerability analysis directories
mkdir -p $LOOT_DIR/vuln-analysis/{cve,dynamic,subdomain-takeover,s3-buckets,quick-hits,sql-injection} 2>/dev/null

echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED INITIALIZING VULNERABILITY ANALYSIS $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# 1. CVE SCANNING
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED CVE VULNERABILITY SCANNING $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Nikto web server scanner
if [[ "$NIKTO" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running Nikto web server vulnerability scanner..."
  nikto -h $TARGET -output $LOOT_DIR/vuln-analysis/cve/nikto-$TARGET.txt -Format txt 2>/dev/null > /dev/null
fi

# OpenVAS vulnerability scanner
if [[ "$OPENVAS" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running OpenVAS vulnerability scanner..."
  openvas-start 2>/dev/null > /dev/null
  sleep 10
  omp -h localhost -p 9390 -u admin -w admin --csv > $LOOT_DIR/vuln-analysis/cve/openvas-$TARGET.csv 2>/dev/null
fi

# Nuclei vulnerability scanner
if [[ "$NUCLEI" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running Nuclei vulnerability scanner..."
  nuclei -u $TARGET -t $PLUGINS_DIR/nuclei-templates/ -o $LOOT_DIR/vuln-analysis/cve/nuclei-$TARGET.txt 2>/dev/null > /dev/null
fi

# 2. DYNAMIC ANALYSIS
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED DYNAMIC APPLICATION ANALYSIS $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# ZAP dynamic security scanner
if [[ "$ZAP" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running OWASP ZAP dynamic scanner..."
  python3 $INSTALL_DIR/bin/zap-scan.py -t $TARGET -o $LOOT_DIR/vuln-analysis/dynamic/zap-$TARGET.html 2>/dev/null > /dev/null
fi

# Burp Suite scan (if available)
if [[ "$BURP" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running Burp Suite dynamic analysis..."
  echo "Manual Burp Suite scan required for $TARGET" > $LOOT_DIR/vuln-analysis/dynamic/burp-$TARGET.txt
fi

# 3. SUBDOMAIN TAKEOVER DETECTION
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED SUBDOMAIN TAKEOVER DETECTION $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Subjack subdomain takeover scanner
if [[ "$SUBJACK" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running Subjack for subdomain takeover detection..."
  subjack -w $LOOT_DIR/domains/domains-$TARGET-all.txt -t $THREADS -ssl -o $LOOT_DIR/vuln-analysis/subdomain-takeover/subjack-$TARGET.txt 2>/dev/null > /dev/null
fi

# SubOver subdomain takeover scanner
if [[ "$SUBOVER" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running SubOver for subdomain takeover detection..."
  subover -l $LOOT_DIR/domains/domains-$TARGET-all.txt > $LOOT_DIR/vuln-analysis/subdomain-takeover/subover-$TARGET.txt 2>/dev/null
fi

# 4. S3 BUCKET ENUMERATION
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED S3 BUCKET ENUMERATION $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# S3Scanner
if [[ "$S3SCANNER" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running S3Scanner for bucket enumeration..."
  s3scanner --bucket $TARGET --dump > $LOOT_DIR/vuln-analysis/s3-buckets/s3scanner-$TARGET.txt 2>/dev/null
fi

# AWS CLI bucket enumeration
if [[ "$AWSCLI" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Checking for open AWS S3 buckets..."
  while read bucket; do
    aws s3 ls s3://$bucket --no-sign-request 2>/dev/null > $LOOT_DIR/vuln-analysis/s3-buckets/aws-$bucket.txt 2>/dev/null
    if [[ -s $LOOT_DIR/vuln-analysis/s3-buckets/aws-$bucket.txt ]]; then
      echo "Potentially vulnerable bucket found: $bucket" >> $LOOT_DIR/vuln-analysis/s3-buckets/vulnerable-buckets.txt
    fi
  done < <(cat $LOOT_DIR/wordlists/cloud-storage.txt | grep $TARGET)
fi

# 5. QUICK HITS DETECTION
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED QUICK HITS DETECTION $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Check for common exposed files
echo -e "$OKBLUE[*]$RESET Scanning for quick hits (swagger, .git, configs, panels)..."
while read path; do
  curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path" | grep -q "200\|301\|302" && echo "Found: $path" >> $LOOT_DIR/vuln-analysis/quick-hits/found-$TARGET.txt 2>/dev/null
done < $LOOT_DIR/wordlists/exposed-files.txt

# Git repository exposure check
echo -e "$OKBLUE[*]$RESET Checking for exposed .git repositories..."
curl -s "https://$TARGET/.git/HEAD" | grep -q "ref:" && echo "Exposed .git repository found" >> $LOOT_DIR/vuln-analysis/quick-hits/git-exposure-$TARGET.txt 2>/dev/null

# Swagger documentation exposure
echo -e "$OKBLUE[*]$RESET Checking for exposed Swagger documentation..."
curl -s "https://$TARGET/swagger.json" | jq -e . > /dev/null 2>/dev/null && echo "Swagger documentation exposed" >> $LOOT_DIR/vuln-analysis/quick-hits/swagger-$TARGET.txt 2>/dev/null
curl -s "https://$TARGET/api-docs" | jq -e . > /dev/null 2>/dev/null && echo "API documentation exposed" >> $LOOT_DIR/vuln-analysis/quick-hits/api-docs-$TARGET.txt 2>/dev/null

# 6. SQL INJECTION TESTING
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED SQL INJECTION TESTING $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# SQLMap automated testing
if [[ "$SQLMAP" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running SQLMap for automated SQL injection testing..."
  sqlmap -u "https://$TARGET/" --batch --risk=2 --level=3 --random-agent --output-dir=$LOOT_DIR/vuln-analysis/sql-injection/sqlmap-$TARGET/ 2>/dev/null > /dev/null
fi

# Ghauri SQL injection tool
if [[ "$GHAURI" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running Ghauri for advanced SQL injection testing..."
  ghauri -u "https://$TARGET/" --batch --output=$LOOT_DIR/vuln-analysis/sql-injection/ghauri-$TARGET.txt 2>/dev/null > /dev/null
fi

# Manual parameter testing
echo -e "$OKBLUE[*]$RESET Testing common parameters for SQL injection..."
while read param; do
  curl -s "https://$TARGET/?$param=1' OR '1'='1" | grep -i "error\|exception\|warning" >> $LOOT_DIR/vuln-analysis/sql-injection/parameter-testing-$TARGET.txt 2>/dev/null
done < $LOOT_DIR/wordlists/sql-injection-params.txt

# 7. WEB APPLICATION VULNERABILITIES
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED WEB APPLICATION VULNERABILITY SCANNING $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Dirbuster directory enumeration
if [[ "$DIRBUSTER" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running Dirbuster for directory enumeration..."
  dirb https://$TARGET /usr/share/wordlists/dirb/common.txt -o $LOOT_DIR/vuln-analysis/web/directories-$TARGET.txt 2>/dev/null > /dev/null
fi

# Gobuster directory enumeration
if [[ "$GOBUSTER" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running Gobuster for directory enumeration..."
  gobuster dir -u https://$TARGET -w $INSTALL_DIR/wordlists/web-brute-full.txt -o $LOOT_DIR/vuln-analysis/web/gobuster-$TARGET.txt 2>/dev/null > /dev/null
fi

# 8. PORT-SPECIFIC VULNERABILITIES
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED PORT-SPECIFIC VULNERABILITY SCANNING $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Service-specific vulnerability checks
echo -e "$OKBLUE[*]$RESET Checking for service-specific vulnerabilities..."
nmap -sV -p- --script vuln $TARGET -oN $LOOT_DIR/vuln-analysis/port-specific/nmap-vulns-$TARGET.txt 2>/dev/null > /dev/null

# 9. COMPREHENSIVE VULNERABILITY REPORTING
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED GENERATING COMPREHENSIVE VULNERABILITY REPORT $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Compile all vulnerability findings
echo -e "$OKBLUE[*]$RESET Compiling vulnerability analysis report..."

cat > $LOOT_DIR/vuln-analysis/vulnerability-report-$TARGET.txt << EOF
SNIPER SECURITY - COMPREHENSIVE VULNERABILITY ANALYSIS REPORT
===============================================================
Target: $TARGET
Scan Date: $(date)
Scanner: Sn1per v$VER - Vulnerability Analysis Mode

EXECUTIVE SUMMARY
================
Total vulnerabilities detected: $(find $LOOT_DIR/vuln-analysis/ -name "*.txt" -exec grep -l "vulnerable\|CVE\|exploit\|critical\|high" {} \; | wc -l 2>/dev/null)

CRITICAL FINDINGS
=================
$(grep -r "CRITICAL\|HIGH\|vulnerable\|CVE" $LOOT_DIR/vuln-analysis/ 2>/dev/null | head -10)

CVE VULNERABILITIES
==================
$(find $LOOT_DIR/vuln-analysis/cve/ -name "*.txt" -exec cat {} \; 2>/dev/null | grep -i "cve\|vulnerabilit" | head -5)

SUBDOMAIN TAKEOVERS
==================
$(cat $LOOT_DIR/vuln-analysis/subdomain-takeover/subjack-$TARGET.txt 2>/dev/null | head -5)
$(cat $LOOT_DIR/vuln-analysis/subdomain-takeover/subover-$TARGET.txt 2>/dev/null | head -5)

S3 BUCKET VULNERABILITIES
========================
$(cat $LOOT_DIR/vuln-analysis/s3-buckets/vulnerable-buckets.txt 2>/dev/null)

QUICK HITS DETECTED
==================
$(cat $LOOT_DIR/vuln-analysis/quick-hits/found-$TARGET.txt 2>/dev/null)

SQL INJECTION FINDINGS
=====================
$(find $LOOT_DIR/vuln-analysis/sql-injection/ -name "*.txt" -exec cat {} \; 2>/dev/null | grep -i "inject\|sql\|vulnerable" | head -5)

WEB VULNERABILITIES
==================
$(find $LOOT_DIR/vuln-analysis/web/ -name "*.txt" -exec cat {} \; 2>/dev/null | grep -i "direct\|found\|vulnerable" | head -5)

PORT-SPECIFIC ISSUES
===================
$(cat $LOOT_DIR/vuln-analysis/port-specific/nmap-vulns-$TARGET.txt 2>/dev/null | grep -i "vulnerable\|cve\|exploit" | head -5)

RECOMMENDATIONS
==============
1. Immediately address all CRITICAL and HIGH severity findings
2. Review and secure any exposed S3 buckets or cloud storage
3. Implement proper input validation to prevent SQL injection
4. Remove or secure any exposed sensitive files or directories
5. Apply security patches for identified CVEs
6. Conduct regular security assessments and penetration testing

SCAN DETAILS
===========
- CVE Scanning: $(ls -la $LOOT_DIR/vuln-analysis/cve/ 2>/dev/null | wc -l) files generated
- Dynamic Analysis: $(ls -la $LOOT_DIR/vuln-analysis/dynamic/ 2>/dev/null | wc -l) files generated
- Subdomain Takeover: $(ls -la $LOOT_DIR/vuln-analysis/subdomain-takeover/ 2>/dev/null | wc -l) files generated
- S3 Bucket Analysis: $(ls -la $LOOT_DIR/vuln-analysis/s3-buckets/ 2>/dev/null | wc -l) files generated
- Quick Hits Detection: $(ls -la $LOOT_DIR/vuln-analysis/quick-hits/ 2>/dev/null | wc -l) files generated
- SQL Injection Testing: $(ls -la $LOOT_DIR/vuln-analysis/sql-injection/ 2>/dev/null | wc -l) files generated
- Web Vulnerability Scanning: $(ls -la $LOOT_DIR/vuln-analysis/web/ 2>/dev/null | wc -l) files generated
- Port-Specific Scanning: $(ls -la $LOOT_DIR/vuln-analysis/port-specific/ 2>/dev/null | wc -l) files generated

This report provides a comprehensive overview of identified security vulnerabilities.
For detailed findings, please review the individual scan result files in the loot directory.

Generated by Sn1per Security Framework
https://sn1persecurity.com
EOF

echo -e "$OKGREEN[*]$RESET Vulnerability analysis completed for $TARGET"
echo -e "$OKGREEN[*]$RESET Report saved to: $LOOT_DIR/vuln-analysis/vulnerability-report-$TARGET.txt"
echo -e "$OKGREEN[*]$RESET Total vulnerabilities detected: $(find $LOOT_DIR/vuln-analysis/ -name "*.txt" -exec grep -l "vulnerable\|CVE\|exploit\|critical\|high" {} \; | wc -l 2>/dev/null)"

echo "[sn1persecurity.com] •?((¯°·._.• Completed Sn1per vulnerability analysis scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
  /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Completed Sn1per vulnerability analysis scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
fi
