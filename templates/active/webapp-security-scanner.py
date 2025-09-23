#!/usr/bin/env python3
"""
Sn1per Advanced Web Application Security Module
Enhanced attack surface management for modern web applications
"""

import json
import re
import sys
import time
import requests
import argparse
import logging
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebAppScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Sn1per-WebAppScanner/2.0'})
        self.findings = {'api_endpoints': [], 'js_vulnerabilities': []}
    
    def scan(self):
        logger.info(f"Scanning: {self.target_url}")
        self._basic_recon()
        self._api_discovery()
        return self.findings
    
    def _basic_recon(self):
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract JS files
            js_files = []
            for script in soup.find_all('script', src=True):
                js_files.append(urljoin(self.target_url, script['src']))
            self.js_files = js_files
            
            # Look for API patterns
            api_patterns = re.findall(r'["\'](/api/[^"\']*)["\']', response.text)
            logger.info(f"Found {len(api_patterns)} potential API endpoints")
            
        except Exception as e:
            logger.error(f"Error in basic recon: {e}")
    
    def _api_discovery(self):
        for js_file in self.js_files[:5]:  # Test first 5 JS files
            try:
                response = self.session.get(js_file, timeout=10)
                if response.status_code == 200:
                    # Look for API calls in JS
                    api_calls = re.findall(r'fetch\(["\']([^"\']*api[^"\']*)["\']', response.text)
                    api_calls.extend(re.findall(r'axios\.get\(["\']([^"\']*api[^"\']*)["\']', response.text))
                    
                    for api_call in api_calls:
                        full_url = urljoin(self.target_url, api_call)
                        self.findings['api_endpoints'].append({
                            'url': full_url,
                            'source': js_file,
                            'method': 'GET'
                        })
            except:
                pass
        
        logger.info(f"Discovered {len(self.findings['api_endpoints'])} API endpoints")

def main():
    parser = argparse.ArgumentParser(description='Sn1per Web Application Security Scanner')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not (args.target.startswith('http://') or args.target.startswith('https://')):
        args.target = f'http://{args.target}'
    
    scanner = WebAppScanner(args.target)
    results = scanner.scan()
    
    print(f"\nScan completed!")
    print(f"API Endpoints: {len(results['api_endpoints'])}")
    print(f"JS Files Analyzed: {len(results.get('js_files', []))}")
    
    # Save results
    with open('webapp-scan-results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("Results saved to: webapp-scan-results.json")

if __name__ == "__main__":
    main()
