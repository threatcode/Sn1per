# Sn1per Advanced Web Application Security Module

This module provides comprehensive web application security testing capabilities for the Sn1per Attack Surface Management Platform.

## Features

### 🔍 **API Discovery & Testing**
- **REST API Discovery**: Automatically discovers REST API endpoints using wordlists
- **GraphQL Analysis**: Detects and tests GraphQL endpoints with introspection
- **API Fuzzing**: Tests discovered endpoints with various HTTP methods
- **Schema Analysis**: Extracts and analyzes API schemas

### 🛡️ **JavaScript Security Analysis**
- **Framework Detection**: Identifies React, Angular, Vue.js, jQuery, etc.
- **DOM XSS Detection**: Finds potential DOM-based XSS vulnerabilities
- **Client-side Security**: Analyzes client-side security configurations
- **Sensitive Data Detection**: Identifies hardcoded credentials and tokens

### 🌐 **Modern Web Vulnerability Detection**
- **CORS Analysis**: Tests for overly permissive CORS policies
- **CSP Analysis**: Evaluates Content Security Policy configurations
- **Security Headers**: Analyzes HTTP security headers
- **Subdomain Takeover**: Checks for potential subdomain takeover scenarios

### 🔧 **Integration Features**
- **Nuclei Templates**: Integrates with Nuclei for vulnerability scanning
- **ZAP Automation**: Works alongside existing ZAP scanning capabilities
- **Wayback Machine**: Leverages historical URL data from waybackurls
- **Screenshot Analysis**: Integrates with webscreenshot for visual analysis

## Installation Requirements

### Dependencies
```bash
pip install requests beautifulsoup4 pyyaml selenium
```

### External Tools
- **Nuclei**: For template-based vulnerability scanning
- **ZAP**: For advanced web application scanning (optional)
- **Wordlists**: API endpoint wordlists (e.g., from SecLists)

## Usage

### Basic Usage
```bash
python3 webapp-security-scanner.py https://example.com
```

### Advanced Usage
```bash
# With custom configuration
python3 webapp-security-scanner.py https://example.com -c webapp-config.yaml

# Verbose output
python3 webapp-security-scanner.py https://example.com -v

# Custom output directory
python3 webapp-security-scanner.py https://example.com -o ./reports/
```

### Configuration File

Create a `webapp-config.yaml` file to customize scanning behavior:

```yaml
api_discovery:
  enable_graphql: true
  enable_rest: true
  wordlist: '/usr/share/wordlists/api-endpoints.txt'

js_analysis:
  enable_client_side: true
  check_frameworks: true

web_vulns:
  check_cors: true
  check_csp: true
  check_headers: true

nuclei:
  enabled: true
  severity: ['high', 'critical']

reporting:
  format: ['json', 'html', 'txt']
  output_dir: './reports'
```

## Output

The scanner generates comprehensive reports in multiple formats:

### 📊 **JSON Report** (`webapp-security-report.json`)
- Complete scan results in JSON format
- Suitable for integration with other tools
- Contains all findings with metadata

### 🌐 **HTML Report** (`webapp-security-report.html`)
- Interactive web-based report
- Color-coded severity levels
- Detailed findings with recommendations

### 📝 **Text Report** (`webapp-security-report.txt`)
- Plain text summary
- Easy to read console output
- Quick overview of findings

## Report Structure

The scanner identifies and reports on:

1. **API Endpoints**
   - Discovered REST/GraphQL endpoints
   - HTTP methods supported
   - Response codes and content types

2. **JavaScript Vulnerabilities**
   - Detected frameworks
   - Potential DOM XSS patterns
   - Sensitive data exposure

3. **CORS Issues**
   - Overly permissive configurations
   - Credential handling problems
   - Origin validation issues

4. **CSP Issues**
   - Unsafe inline/eval policies
   - Missing security directives
   - Wildcard source problems

5. **Security Headers**
   - Missing security headers
   - Incorrect configurations
   - Best practice recommendations

6. **Web Vulnerabilities**
   - Nuclei findings
   - OWASP Top 10 issues
   - Zero-day detection

## Integration with Sn1per

### Integration Points

1. **ZAP Enhancement**: Works alongside `zap-scan.py` for comprehensive scanning
2. **URL Discovery**: Integrates with `waybackurls.py` for historical analysis
3. **Screenshot Correlation**: Uses `webscreenshot.py` for visual verification
4. **Subdomain Enumeration**: Complements `github-subdomains.py` findings

### Workflow Integration

```
Sn1per Reconnaissance
       ↓
Subdomain Discovery (github-subdomains.py)
       ↓
Web Application Scanning (webapp-security-scanner.py)
       ↓
Screenshot Analysis (webscreenshot.py)
       ↓
Vulnerability Scanning (zap-scan.py)
       ↓
Report Generation
```

## Security Considerations

- **Rate Limiting**: Respects target rate limits
- **Safe Testing**: Non-destructive testing methods
- **SSL Verification**: Validates SSL certificates
- **Timeout Handling**: Prevents hanging requests
- **Error Handling**: Graceful failure handling

## Troubleshooting

### Common Issues

1. **Missing Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Permission Errors**
   - Ensure proper file permissions
   - Check write access to output directory

3. **Network Issues**
   - Verify target accessibility
   - Check firewall/proxy settings

4. **Memory Issues**
   - Large targets may require more memory
   - Consider processing in batches

### Debug Mode

Enable verbose logging for troubleshooting:
```bash
python3 webapp-security-scanner.py https://example.com -v
```

## Contributing

To contribute to the Web Application Security Module:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure compatibility with existing Sn1per tools
5. Submit a pull request

## License

This module is part of the Sn1per Attack Surface Management Platform.

---

**Note**: This tool is designed for authorized penetration testing and security research only. Always obtain proper authorization before scanning any target.
