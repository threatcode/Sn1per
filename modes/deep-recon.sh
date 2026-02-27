#!/bin/bash
# DEEP RECON SCAN #####################################################################################################
# Advanced reconnaissance techniques for comprehensive attack surface mapping

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
  if [[ "$MODE" = "port" ]]; then
    args="$args -m port"
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
echo -e "$OKORANGE + -- --=[Deep Recon Mode - Advanced Attack Surface Mapping"
echo -e "$RESET"

if [[ ! -z $WORKSPACE ]]; then
  LOOT_DIR=$WORKSPACE_DIR
fi

echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
if [[ "$MODE" = "" ]]; then
  MODE="deep-recon"
  echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
else
  echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
fi
echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/${TARGET}-${MODE}.txt 2> /dev/null
echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt

echo "[sn1persecurity.com] •?((¯°·._.• Started Sn1per deep recon scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
  /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Sn1per deep recon scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
fi

# Initialize deep recon directories
mkdir -p $LOOT_DIR/deep-recon/{ssl,analytics,supply-chain,google-fu,tlds,o365,shodan,asn,crunchbase,dmarc,favicon,esoteric} 2>/dev/null

echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED INITIALIZING DEEP RECONNAISSANCE $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# 1. DOMAIN RECONNAISSANCE
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED ADVANCED DOMAIN RECONNAISSANCE $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# DNS enumeration with multiple tools
if [[ "$SUBLIST3R" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running Sublist3r for subdomain enumeration..."
  python3 $PLUGINS_DIR/Sublist3r/sublist3r.py -d $TARGET -vvv -o $LOOT_DIR/domains/domains-$TARGET-sublist3r.txt 2>/dev/null > /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-sublist3r.txt 2>/dev/null | grep $TARGET >> $LOOT_DIR/domains/domains-$TARGET-full.txt 2>/dev/null
fi

if [[ "$AMASS" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running Amass for comprehensive subdomain enumeration..."
  amass enum -ip -o $LOOT_DIR/domains/domains-$TARGET-amass.txt -rf $PLUGINS_DIR/massdns/lists/resolvers.txt -d $TARGET 2>/dev/null > /dev/null
  cut -d" " -f1 $LOOT_DIR/domains/domains-$TARGET-amass.txt 2>/dev/null | grep $TARGET > $LOOT_DIR/domains/domains-$TARGET-amass-sorted.txt
  cut -d" " -f2 $LOOT_DIR/domains/domains-$TARGET-amass.txt 2>/dev/null > $LOOT_DIR/ips/amass-ips-$TARGET.txt

  # Reverse WHOIS lookup
  echo -e "$OKBLUE[*]$RESET Running Amass reverse WHOIS lookup..."
  amass intel -whois -d $TARGET > $LOOT_DIR/domains/domains-$TARGET-reverse-whois.txt 2> /dev/null
fi

if [[ "$SUBFINDER" = "1" ]]; then
  echo -e "$OKBLUE[*]$RESET Running Subfinder for fast subdomain enumeration..."
  subfinder -o $LOOT_DIR/domains/domains-$TARGET-subfinder.txt -d $TARGET -nW -rL $INSTALL_DIR/wordlists/resolvers.txt -t $THREADS 2>/dev/null > /dev/null
fi

# Certificate Transparency logs
echo -e "$OKBLUE[*]$RESET Gathering certificate subdomains from crt.sh..."
curl -s "https://crt.sh/?q=%25.$TARGET" > $LOOT_DIR/deep-recon/ssl/crt-$TARGET-raw.txt
cat $LOOT_DIR/deep-recon/ssl/crt-$TARGET-raw.txt | grep $TARGET | grep TD | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/BR/\n/g' | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | grep -v "*" | sort -u > $LOOT_DIR/domains/domains-$TARGET-crt.txt

# Project Sonar
echo -e "$OKBLUE[*]$RESET Gathering subdomains from Project Sonar..."
curl -fsSL "https://dns.bufferover.run/dns?q=.$TARGET" | sed 's/\"//g' | cut -f2 -d "," | grep -v "<BR>" | sort -u | grep $TARGET > $LOOT_DIR/domains/domains-$TARGET-projectsonar.txt

# RapidDNS
echo -e "$OKBLUE[*]$RESET Gathering subdomains from RapidDNS..."
curl -s "https://rapiddns.io/subdomain/$TARGET?full=1&down=1#exportData()" | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u | grep "$TARGET" | cut -d\/ -f3 > $LOOT_DIR/domains/domains-$TARGET-rapiddns.txt

# 2. SHODAN INTEGRATION
if [[ "$SHODAN" = "1" ]] && [[ ! -z "$SHODAN_API_KEY" ]]; then
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED SHODAN ASSET DISCOVERY $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

  shodan init $SHODAN_API_KEY
  echo -e "$OKBLUE[*]$RESET Searching for $TARGET on Shodan..."
  shodan search "hostname:*.$TARGET" > $LOOT_DIR/deep-recon/shodan/shodan-$TARGET.txt 2> /dev/null
  awk '{print $3}' $LOOT_DIR/deep-recon/shodan/shodan-$TARGET.txt 2> /dev/null | grep -v "\;" > $LOOT_DIR/domains/domains-$TARGET-shodan.txt 2> /dev/null
  awk '{print $1}' $LOOT_DIR/deep-recon/shodan/shodan-$TARGET.txt 2> /dev/null >> $LOOT_DIR/ips/ips-all-unsorted.txt 2>/dev/null

  # Shodan host enumeration
  echo -e "$OKBLUE[*]$RESET Enumerating Shodan hosts for $TARGET..."
  shodan search "org:$TARGET" > $LOOT_DIR/deep-recon/shodan/shodan-org-$TARGET.txt 2> /dev/null
  shodan search "ssl:$TARGET" > $LOOT_DIR/deep-recon/shodan/shodan-ssl-$TARGET.txt 2> /dev/null

  # Shodan vulnerabilities
  echo -e "$OKBLUE[*]$RESET Searching for vulnerabilities on Shodan..."
  shodan search "vuln:$TARGET" > $LOOT_DIR/deep-recon/shodan/shodan-vulns-$TARGET.txt 2> /dev/null
fi

# 3. ASN ANALYSIS
if [[ "$ASN_CHECK" = "1" ]]; then
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED ASN ANALYSIS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

  # Get ASN information
  whois -h whois.cymru.com " -v $TARGET" > $LOOT_DIR/deep-recon/asn/asn-$TARGET.txt 2>/dev/null
  ASN=$(grep "^AS" $LOOT_DIR/deep-recon/asn/asn-$TARGET.txt | awk '{print $1}' | cut -d'|' -f1 | tr -d 'AS')

  if [[ ! -z "$ASN" ]]; then
    echo -e "$OKBLUE[*]$RESET Found ASN: $ASN for $TARGET"
    echo -e "$OKBLUE[*]$RESET Enumerating all IPs in ASN $ASN..."
    whois -h whois.radb.net "!g$ASN" | grep -v "^%" | grep -v "^$" | grep -v "^AS" | sort -u > $LOOT_DIR/deep-recon/asn/asn-$ASN-ips.txt

    # BGP Toolkit
    echo -e "$OKBLUE[*]$RESET Gathering BGP information..."
    curl -s "https://api.bgpview.io/asn/$ASN/prefixes" | jq -r '.data.ipv4_prefixes[].prefix' 2>/dev/null > $LOOT_DIR/deep-recon/asn/asn-$ASN-prefixes.txt
    curl -s "https://api.bgpview.io/asn/$ASN/peers" | jq -r '.data[].asn' 2>/dev/null > $LOOT_DIR/deep-recon/asn/asn-$ASN-peers.txt

    # Hurricane Electric BGP Toolkit
    echo -e "$OKBLUE[*]$RESET Gathering BGP information from Hurricane Electric..."
    curl -s "https://bgp.he.net/AS$ASN" > $LOOT_DIR/deep-recon/asn/asn-$ASN-bgp.html
    cat $LOOT_DIR/deep-recon/asn/asn-$ASN-bgp.html | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/[0-9]\{1,2\}' | sort -u > $LOOT_DIR/deep-recon/asn/asn-$ASN-prefixes-he.txt
  fi
fi

# 4. CRUNCHBASE INTEGRATION
if [[ ! -z "$CRUNCHBASE_API_KEY" ]]; then
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED CRUNCHBASE COMPANY INTELLIGENCE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

  # Extract company name from target domain
  COMPANY=$(echo $TARGET | sed 's/\..*//g' | sed 's/[^a-zA-Z0-9]//g')
  echo -e "$OKBLUE[*]$RESET Searching Crunchbase for: $COMPANY"

  curl -s "https://api.crunchbase.com/api/v4/autocompletes?query=$COMPANY" -H "X-cb-api-key: $CRUNCHBASE_API_KEY" > $LOOT_DIR/deep-recon/crunchbase/crunchbase-$COMPANY.json 2>/dev/null

  if [[ -s $LOOT_DIR/deep-recon/crunchbase/crunchbase-$COMPANY.json ]]; then
    # Parse company information
    cat $LOOT_DIR/deep-recon/crunchbase/crunchbase-$COMPANY.json | jq -r '.entities[].identifier' 2>/dev/null > $LOOT_DIR/deep-recon/crunchbase/crunchbase-companies.txt

    # Get detailed company information
    while read company_id; do
      curl -s "https://api.crunchbase.com/api/v4/entities/organizations/$company_id" -H "X-cb-api-key: $CRUNCHBASE_API_KEY" > $LOOT_DIR/deep-recon/crunchbase/company-$company_id.json 2>/dev/null

      # Extract related domains
      cat $LOOT_DIR/deep-recon/crunchbase/company-$company_id.json | jq -r '.properties.homepage_url' 2>/dev/null >> $LOOT_DIR/deep-recon/crunchbase/company-domains.txt 2>/dev/null
      cat $LOOT_DIR/deep-recon/crunchbase/company-$company_id.json | jq -r '.properties.domain_aliases[]' 2>/dev/null >> $LOOT_DIR/deep-recon/crunchbase/company-domains.txt 2>/dev/null
    done < $LOOT_DIR/deep-recon/crunchbase/crunchbase-companies.txt
  fi
fi

# 5. SSL/TLS RECONNAISSANCE
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED SSL/TLS RECONNAISSANCE $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# SSL Labs analysis
echo -e "$OKBLUE[*]$RESET Analyzing SSL configuration with SSL Labs..."
curl -s "https://api.ssllabs.com/api/v3/analyze?host=$TARGET" > $LOOT_DIR/deep-recon/ssl/ssllabs-$TARGET.json 2>/dev/null

# Certificate analysis
echo -e "$OKBLUE[*]$RESET Analyzing SSL certificates..."
timeout 10 openssl s_client -connect $TARGET:443 -servername $TARGET </dev/null 2>/dev/null | openssl x509 -noout -text > $LOOT_DIR/deep-recon/ssl/cert-$TARGET.txt 2>/dev/null

# Certificate chain analysis
echo -e "$OKBLUE[*]$RESET Analyzing certificate chain..."
echo | timeout 10 openssl s_client -connect $TARGET:443 -servername $TARGET -showcerts 2>/dev/null | sed -n '/Certificate chain/,/Server certificate/p' > $LOOT_DIR/deep-recon/ssl/cert-chain-$TARGET.txt 2>/dev/null

# 6. REVERSE WHOIS & DNS
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED REVERSE WHOIS & DNS ANALYSIS $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Reverse WHOIS lookup
echo -e "$OKBLUE[*]$RESET Performing reverse WHOIS lookups..."
whois $TARGET > $LOOT_DIR/deep-recon/whois/whois-$TARGET.txt 2>/dev/null

# Extract email addresses from WHOIS
cat $LOOT_DIR/deep-recon/whois/whois-$TARGET.txt | grep -i "registrant email\|admin email\|tech email" | grep -o '[a-zA-Z0-9._-]*@[a-zA-Z0-9._-]*' > $LOOT_DIR/deep-recon/whois/emails-$TARGET.txt

# Reverse DNS lookups
echo -e "$OKBLUE[*]$RESET Performing reverse DNS lookups..."
host $TARGET > $LOOT_DIR/deep-recon/dns/reverse-dns-$TARGET.txt 2>/dev/null

# 7. DMARC ANALYSIS
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED DMARC/SPF/DKIM ANALYSIS $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# DMARC record check
echo -e "$OKBLUE[*]$RESET Checking DMARC records..."
dig TXT _dmarc.$TARGET > $LOOT_DIR/deep-recon/dmarc/dmarc-$TARGET.txt 2>/dev/null

# SPF record check
echo -e "$OKBLUE[*]$RESET Checking SPF records..."
dig TXT $TARGET | grep -i spf > $LOOT_DIR/deep-recon/dmarc/spf-$TARGET.txt 2>/dev/null

# DKIM record check
echo -e "$OKBLUE[*]$RESET Checking DKIM records..."
for selector in default k1 k2 google mail; do
  dig TXT $selector._domainkey.$TARGET > $LOOT_DIR/deep-recon/dmarc/dkim-$selector-$TARGET.txt 2>/dev/null
done

# 8. ANALYTICS RELATIONSHIPS
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED ANALYTICS RELATIONSHIPS MAPPING $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Google Analytics detection
echo -e "$OKBLUE[*]$RESET Searching for Google Analytics IDs..."
curl -s "https://$TARGET" | grep -o 'UA-[0-9]*-[0-9]*\|G-[A-Z0-9]*' > $LOOT_DIR/deep-recon/analytics/ga-$TARGET.txt 2>/dev/null

# Google Tag Manager detection
echo -e "$OKBLUE[*]$RESET Searching for Google Tag Manager IDs..."
curl -s "https://$TARGET" | grep -o 'GTM-[A-Z0-9]*' > $LOOT_DIR/deep-recon/analytics/gtm-$TARGET.txt 2>/dev/null

# 9. SUPPLY CHAIN INVESTIGATION
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED SUPPLY CHAIN & SaaS DISCOVERY $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Third-party service detection
echo -e "$OKBLUE[*]$RESET Analyzing third-party services..."
curl -s "https://$TARGET" | grep -o 'src="[^"]*\|href="[^"]*' | grep -E '\.(js|css)' | sort -u > $LOOT_DIR/deep-recon/supply-chain/third-party-$TARGET.txt

# CDN detection
echo -e "$OKBLUE[*]$RESET Detecting CDN usage..."
curl -s -I "https://$TARGET" | grep -i "server\|x-served-by\|x-amz\|x-cache" > $LOOT_DIR/deep-recon/supply-chain/cdn-$TARGET.txt

# 10. GOOGLE-FU TECHNIQUES
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED GOOGLE-FU INTELLIGENCE GATHERING $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Privacy policy analysis
echo -e "$OKBLUE[*]$RESET Analyzing privacy policy..."
curl -s "https://$TARGET/privacy-policy\|https://$TARGET/privacy" > $LOOT_DIR/deep-recon/google-fu/privacy-policy-$TARGET.html 2>/dev/null

# Trademark search (simulated)
echo -e "$OKBLUE[*]$RESET Searching for trademarks..."
echo "site:uspto.gov $TARGET" > $LOOT_DIR/deep-recon/google-fu/trademark-search-$TARGET.txt

# 11. TLD SCANNING
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED TLD ENUMERATION $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Common TLD enumeration
for tld in com net org info biz co uk de fr it es; do
  host $TARGET.$tld > $LOOT_DIR/deep-recon/tlds/tld-$TARGET-$tld.txt 2>/dev/null
done

# 12. O365 ENUMERATION
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED O365 ENUMERATION $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# O365 domain enumeration
echo -e "$OKBLUE[*]$RESET Checking for O365 services..."
for service in autodiscover autoconfig lyncdiscover enterpriseenrollment enterpriseregistration; do
  host $service.$TARGET > $LOOT_DIR/deep-recon/o365/o365-$service-$TARGET.txt 2>/dev/null
done

# 13. FAVICON ANALYSIS
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED FAVICON ANALYSIS $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Download and analyze favicon
echo -e "$OKBLUE[*]$RESET Downloading favicon for analysis..."
curl -s "https://$TARGET/favicon.ico" -o $LOOT_DIR/deep-recon/favicon/favicon-$TARGET.ico 2>/dev/null

# 14. SUB-SUBDOMAIN ENUMERATION
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED SUB-SUBDOMAIN ENUMERATION $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Generate sub-subdomain wordlist
echo -e "$OKBLUE[*]$RESET Generating sub-subdomain permutations..."
for sub in $(cat $LOOT_DIR/domains/domains-$TARGET-full.txt 2>/dev/null); do
  for word in dev test staging api admin; do
    echo "$word.$sub" >> $LOOT_DIR/deep-recon/sub-subdomains/sub-sub-$TARGET.txt 2>/dev/null
  done
done

# 15. ESOTERIC TECHNIQUES
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED ESOTERIC RECONNAISSANCE $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Wayback Machine
echo -e "$OKBLUE[*]$RESET Gathering historical URLs from Wayback Machine..."
curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET&output=json&fl=original" | jq -r '.[].original' 2>/dev/null > $LOOT_DIR/deep-recon/esoteric/wayback-$TARGET.txt

# DNS zone transfer attempts
echo -e "$OKBLUE[*]$RESET Attempting DNS zone transfers..."
for ns in $(dig NS $TARGET | grep -o 'NS.*' | awk '{print $2}'); do
  dig axfr $TARGET @$ns > $LOOT_DIR/deep-recon/esoteric/zonetransfer-$TARGET-$ns.txt 2>/dev/null
done

# Compile all findings
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED COMPILING DEEP RECON FINDINGS $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"

# Aggregate all domains
cat $LOOT_DIR/domains/domains-*-$TARGET*.txt 2>/dev/null | grep $TARGET | sort -u > $LOOT_DIR/domains/domains-$TARGET-all.txt
cat $LOOT_DIR/deep-recon/crunchbase/company-domains.txt 2>/dev/null >> $LOOT_DIR/domains/domains-$TARGET-all.txt 2>/dev/null

# Create comprehensive report
echo -e "$OKBLUE[*]$RESET Generating deep recon summary report..."
cat > $LOOT_DIR/deep-recon/deep-recon-summary-$TARGET.txt << EOF
DEEP RECONNAISSANCE SUMMARY FOR: $TARGET
Generated: $(date)
Scanner: Sn1per v$VER - Deep Recon Mode

DOMAINS DISCOVERED: $(wc -l < $LOOT_DIR/domains/domains-$TARGET-all.txt 2>/dev/null)
IPS DISCOVERED: $(wc -l < $LOOT_DIR/ips/ips-all-unsorted.txt 2>/dev/null)

MODULE RESULTS:
- SSL Analysis: $(ls -la $LOOT_DIR/deep-recon/ssl/ | wc -l) files
- Shodan Results: $(ls -la $LOOT_DIR/deep-recon/shodan/ | wc -l) files
- ASN Analysis: $(ls -la $LOOT_DIR/deep-recon/asn/ | wc -l) files
- Crunchbase: $(ls -la $LOOT_DIR/deep-recon/crunchbase/ | wc -l) files
- Analytics: $(ls -la $LOOT_DIR/deep-recon/analytics/ | wc -l) files
- Supply Chain: $(ls -la $LOOT_DIR/deep-recon/supply-chain/ | wc -l) files
- Esoteric: $(ls -la $LOOT_DIR/deep-recon/esoteric/ | wc -l) files

HIGH PRIORITY FINDINGS:
$(grep -r "vulnerable\|CVE\|exploit\|leak\|credential" $LOOT_DIR/deep-recon/ 2>/dev/null | head -10)

EOF

echo -e "$OKGREEN[*]$RESET Deep reconnaissance completed for $TARGET"
echo -e "$OKGREEN[*]$RESET Report saved to: $LOOT_DIR/deep-recon/deep-recon-summary-$TARGET.txt"
echo -e "$OKGREEN[*]$RESET Total domains discovered: $(wc -l < $LOOT_DIR/domains/domains-$TARGET-all.txt 2>/dev/null)"
echo -e "$OKGREEN[*]$RESET Total IPs discovered: $(wc -l < $LOOT_DIR/ips/ips-all-unsorted.txt 2>/dev/null)"

echo "[sn1persecurity.com] •?((¯°·._.• Completed Sn1per deep recon scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
  /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Completed Sn1per deep recon scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
fi
