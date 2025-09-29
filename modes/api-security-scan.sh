#!/bin/bash
# API Security Scan Mode
# Author: Sn1per Security Team
# Description: Comprehensive API security testing and assessment

if [[ "$API_SECURITY_SCAN" = "1" ]]; then
  echo "[sn1persecurity.com] •?((¯°·._.• Started API Security Scan: $TARGET [api-security-scan] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started API Security Scan: $TARGET [api-security-scan] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi

  mkdir -p $LOOT_DIR/api/$TARGET
  
  # Check if the target is a URL
  if [[ ! $TARGET =~ ^https?:// ]]; then
    TARGET="http://$TARGET"
  fi
  
  # API Discovery
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED DISCOVERING API ENDPOINTS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  
  # Use common API endpoints discovery
  if command -v gau &> /dev/null; then
    echo -e "${OKBLUE}[*]${RESET} Discovering API endpoints with gau..."
    echo $TARGET | gau --subs --threads 10 | grep -iE "\.(json|xml|api|rest|soap|graphql|grpc|rpc)" | sort -u > $LOOT_DIR/api/$TARGET/endpoints-gau.txt
  fi
  
  if command -v waybackurls &> /dev/null; then
    echo -e "${OKBLUE}[*]${RESET} Discovering historical API endpoints with waybackurls..."
    echo $TARGET | waybackurls | grep -iE "\.(json|xml|api|rest|soap|graphql|grpc|rpc)" | sort -u > $LOOT_DIR/api/$TARGET/endpoints-wayback.txt
  fi
  
  # Combine and deduplicate endpoints
  cat $LOOT_DIR/api/$TARGET/endpoints-*.txt 2>/dev/null | sort -u > $LOOT_DIR/api/$TARGET/endpoints-all.txt
  
  # API Documentation Discovery
  echo -e "\n${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED SEARCHING FOR API DOCUMENTATION $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  
  # Common API documentation paths
  DOC_PATHS=("/api/docs" "/swagger" "/swagger-ui" "/swagger-ui.html" "/api/swagger" "/api-docs" 
             "/api-docs/swagger.json" "/v1/api-docs" "/v2/api-docs" "/v3/api-docs" "/openapi" 
             "/openapi.json" "/openapi.yaml" "/openapi.yml" "/api/openapi.json" "/documentation")
  
  for path in "${DOC_PATHS[@]}"; do
    url="${TARGET%/}$path"
    echo -e "${OKBLUE}[*]${RESET} Checking: $url"
    curl -s -k -L --connect-timeout 5 --max-time 10 -o /dev/null -w "%{http_code}" "$url" | grep -q "^[23]" && echo "[+] Found: $url" >> $LOOT_DIR/api/$TARGET/api-docs-found.txt
  done
  
  # API Security Testing
  echo -e "\n${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED PERFORMING API SECURITY TESTS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  
  # Run OWASP ZAP if available
  if [[ "$ZAP_SCAN" = "1" ]] && command -v zap-cli &> /dev/null; then
    echo -e "${OKBLUE}[*]${RESET} Running OWASP ZAP API scan..."
    zap-cli start --start-options '-config api.disablekey=true' > /dev/null 2>&1 &
    ZAP_PID=$!
    sleep 10
    
    zap-cli open-url "$TARGET"
    zap-cli active-scan "$TARGET"
    zap-cli report -o "$LOOT_DIR/api/$TARGET/zap-report.html" -f html
    
    kill $ZAP_PID
  fi
  
  # Run Nuclei for API security checks
  if command -v nuclei &> /dev/null; then
    echo -e "${OKBLUE}[*]${RESET} Running Nuclei API security checks..."
    nuclei -t "$NUCLEI_TEMPLATES_PATH/technologies/" -t "$NUCLEI_TEMPLATES_PATH/vulnerabilities/" -u "$TARGET" -o "$LOOT_DIR/api/$TARGET/nuclei-api-scan.txt" -silent
  fi
  
  # Test for common API vulnerabilities
  echo -e "\n${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED TESTING FOR COMMON API VULNERABILITIES $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  
  # Test for BOLA (Broken Object Level Authorization)
  echo -e "${OKBLUE}[*]${RESET} Testing for BOLA (Broken Object Level Authorization)..."
  if [ -s "$LOOT_DIR/api/$TARGET/endpoints-all.txt" ]; then
    for endpoint in $(grep -E "/[0-9]+/" $LOOT_DIR/api/$TARGET/endpoints-all.txt | head -n 10); do
      # Try to access another user's resource by ID manipulation
      new_id=$(($(echo $endpoint | grep -oE '[0-9]+' | head -n 1) + 1))
      test_url=$(echo $endpoint | sed -E "s|/[0-9]+/|/$new_id/|g")
      status_code=$(curl -s -k -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $API_TOKEN" "$test_url")
      
      if [[ "$status_code" == "200" ]]; then
        echo "[!] Possible BOLA vulnerability found: $test_url" >> "$LOOT_DIR/api/$TARGET/vulnerabilities-bola.txt"
      fi
    done
  fi
  
  # Test for Excessive Data Exposure
  echo -e "${OKBLUE}[*]${RESET} Testing for Excessive Data Exposure..."
  if [ -s "$LOOT_DIR/api/$TARGET/endpoints-all.txt" ]; then
    for endpoint in $(grep -E "\.(json|xml)" $LOOT_DIR/api/$TARGET/endpoints-all.txt | head -n 10); do
      # Check if sensitive data is exposed in the response
      response=$(curl -s -k -H "Authorization: Bearer $API_TOKEN" "$endpoint")
      
      if echo "$response" | grep -qE '(password|token|secret|key|auth|credential)'; then
        echo "[!] Possible Excessive Data Exposure in: $endpoint" >> "$LOOT_DIR/api/$TARGET/vulnerabilities-data-exposure.txt"
        echo "     Exposed sensitive data: $(echo "$response" | grep -Eo '(password|token|secret|key|auth|credential)[^,\"\'\}]*' | head -n 3 | tr '\n' ',')" >> "$LOOT_DIR/api/$TARGET/vulnerabilities-data-exposure.txt"
      fi
    done
  fi
  
  # Test for Security Misconfiguration
  echo -e "${OKBLUE}[*]${RESET} Testing for Security Misconfigurations..."
  # Check for missing security headers
  curl -s -k -I "$TARGET" | grep -iE "(server|x-powered-by|x-aspnet-version|x-aspnetmvc-version)" > "$LOOT_DIR/api/$TARGET/security-headers.txt"
  
  # Check for CORS misconfigurations
  echo -e "${OKBLUE}[*]${RESET} Testing CORS Misconfigurations..."
  curl -s -k -I -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" "$TARGET" | grep -i "access-control" > "$LOOT_DIR/api/$TARGET/cors-test.txt"
  
  # Generate API Security Report
  generate_api_security_report "$TARGET"
  
  echo -e "\n${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED API SECURITY SCAN COMPLETE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  
  echo "[sn1persecurity.com] •?((¯°·._.• Finished API Security Scan: $TARGET [api-security-scan] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Finished API Security Scan: $TARGET [api-security-scan] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
fi

# Generate API Security Report
generate_api_security_report() {
  local target=$1
  local report_file="$LOOT_DIR/api/$target/api-security-report-$(date +%Y%m%d%H%M).html"
  
  # Count findings
  local total_findings=0
  local critical_findings=$(wc -l < "$LOOT_DIR/api/$target/vulnerabilities-bola.txt" 2>/dev/null)
  local exposure_findings=$(wc -l < "$LOOT_DIR/api/$target/vulnerabilities-data-exposure.txt" 2>/dev/null)
  total_findings=$((total_findings + critical_findings + exposure_findings))
  
  cat > "$report_file" << EOL
<!DOCTYPE html>
<html>
<head>
    <title>API Security Assessment Report - $target</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; }
        .finding { background: #f9f9f9; border-left: 4px solid #3498db; padding: 15px; margin-bottom: 15px; border-radius: 4px; }
        .critical { border-left-color: #e74c3c !important; }
        .high { border-left-color: #e67e22 !important; }
        .medium { border-left-color: #f39c12 !important; }
        .low { border-left-color: #2ecc71 !important; }
        pre { 
            background: #f4f4f4; 
            padding: 10px; 
            overflow-x: auto; 
            border-radius: 4px;
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.9em;
        }
        .summary-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }
        .summary-item:last-child {
            border-bottom: none;
        }
        .severity-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }
        .severity-critical { background: #e74c3c; }
        .severity-high { background: #e67e22; }
        .severity-medium { background: #f39c12; }
        .severity-low { background: #2ecc71; }
        .timestamp { 
            color: #7f8c8d; 
            font-size: 0.9em; 
            text-align: center;
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #eee;
        }
        h2 { color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 8px; }
        h3 { color: #34495e; margin-top: 20px; }
        .endpoint { 
            font-family: 'Courier New', Courier, monospace;
            background: #f0f0f0;
            padding: 2px 6px;
            border-radius: 3px;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>API Security Assessment Report</h1>
        <p>Target: $target | Generated: $(date)</p>
    </div>
    
    <div class="summary-card">
        <h2>Executive Summary</h2>
        <div class="summary-item">
            <span>Total Findings:</span>
            <span><strong>$total_findings</strong></span>
        </div>
        <div class="summary-item">
            <span>Critical Findings:</span>
            <span><span class="severity-badge severity-critical">$critical_findings</span></span>
        </div>
        <div class="summary-item">
            <span>Data Exposure Issues:</span>
            <span><span class="severity-badge severity-high">$exposure_findings</span></span>
        </div>
        <div class="summary-item">
            <span>API Endpoints Discovered:</span>
            <span><strong>$(wc -l < "$LOOT_DIR/api/$target/endpoints-all.txt" 2>/dev/null || echo "0")</strong></span>
        </div>
    </div>
    
    <div class="section">
        <h2>Critical Findings</h2>
        
        <div class="finding critical">
            <h3>Broken Object Level Authorization (BOLA)</h3>
            $(if [ -s "$LOOT_DIR/api/$target/vulnerabilities-bola.txt" ]; then
                echo "<p>The following endpoints may be vulnerable to BOLA attacks:</p>"
                echo "<pre>"
                cat "$LOOT_DIR/api/$target/vulnerabilities-bola.txt"
                echo "</pre>"
                echo "<p><strong>Remediation:</strong> Implement proper authorization checks to ensure users can only access resources they are authorized to access.</p>"
            else
                echo "<p>No BOLA vulnerabilities were identified during testing.</p>"
            fi)
        </div>
        
        <div class="finding high">
            <h3>Excessive Data Exposure</h3>
            $(if [ -s "$LOOT_DIR/api/$target/vulnerabilities-data-exposure.txt" ]; then
                echo "<p>The following endpoints may be exposing sensitive data:</p>"
                echo "<pre>"
                cat "$LOOT_DIR/api/$target/vulnerabilities-data-exposure.txt"
                echo "</pre>"
                echo "<p><strong>Remediation:</strong> Review and filter sensitive data in API responses. Only return the minimum required data for each endpoint.</p>"
            else
                echo "<p>No excessive data exposure issues were identified during testing.</p>"
            fi)
        </div>
    </div>
    
    <div class="section">
        <h2>API Endpoints Discovered</h2>
        $(if [ -s "$LOOT_DIR/api/$target/endpoints-all.txt" ]; then
            echo "<p>Total endpoints discovered: $(wc -l < "$LOOT_DIR/api/$target/endpoints-all.txt")</p>"
            echo "<div style='max-height: 300px; overflow-y: auto; border: 1px solid #eee; padding: 10px; border-radius: 4px;'>"
            echo "<pre>"
            head -n 50 "$LOOT_DIR/api/$target/endpoints-all.txt"
            [ $(wc -l < "$LOOT_DIR/api/$target/endpoints-all.txt") -gt 50 ] && echo "\n... and more (truncated)"
            echo "</pre>"
            echo "</div>"
            echo "<p><em>Full list available at: $LOOT_DIR/api/$target/endpoints-all.txt</em></p>"
        else
            echo "<p>No API endpoints were discovered during testing.</p>"
        fi)
    </div>
    
    <div class="section">
        <h2>Security Headers</h2>
        $(if [ -s "$LOOT_DIR/api/$target/security-headers.txt" ]; then
            echo "<p>The following security-related headers were identified:</p>"
            echo "<pre>"
            cat "$LOOT_DIR/api/$target/security-headers.txt"
            echo "</pre>"
            echo "<p><strong>Recommendation:</strong> Ensure proper security headers are implemented (e.g., Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, etc.).</p>"
        else
            echo "<p>No security headers were identified in the response.</p>"
        fi)
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <div class="finding low">
            <h3>General Security Recommendations</h3>
            <ul>
                <li>Implement proper authentication and authorization for all API endpoints</li>
                <li>Use HTTPS for all API communications</li>
                <li>Implement rate limiting to prevent abuse</li>
                <li>Validate and sanitize all input data</li>
                <li>Implement proper error handling that doesn't leak sensitive information</li>
                <li>Regularly update and patch all API dependencies</li>
                <li>Implement proper logging and monitoring</li>
                <li>Conduct regular security assessments and penetration tests</li>
            </ul>
        </div>
    </div>
    
    <div class="timestamp">
        Report generated by Sn1per Professional v$VERSION on $(date)
    </div>
</body>
</html>
EOL

  echo -e "${OKGREEN}[*]${RESET} API security report generated: $report_file"
}
