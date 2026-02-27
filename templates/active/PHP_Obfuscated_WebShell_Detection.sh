AUTHOR='@xer0dayz'
VULN_NAME='PHP Obfuscated Web Shell Detection'
METHOD='POST'
SEVERITY='P1 - CRITICAL'
CURL_OPTS="--user-agent 'Mozilla/5.0' -s -L --insecure"
SECONDARY_COMMANDS='''
# Common obfuscated shell patterns
PATTERNS=(
  'base64_decode.*\$_POST'
  'gzinflate.*base64_decode'
  'str_rot13.*eval'
  'create_function.*\$_REQUEST'
  'preg_replace.*/e.*\$\w+\('
  'assert.*\$_(POST|GET|REQUEST)'
  'call_user_func.*\$_(POST|GET|REQUEST)'
  '\$\w+\s*=\s*[\'\"]\s*[a-zA-Z0-9+/=]{20,}'
  '\\x[0-9a-fA-F]{2}'
  '\\([0-7]{1,3}|x[0-9a-fA-F]{1,2})'
)

# Search for obfuscated PHP files
find /var/www -type f -name "*.php" -exec grep -lE "$(IFS="|"; echo "${PATTERNS[*]}")" {} \; 2>/dev/null | while read -r file; do
  echo "[!] Suspicious file found: $file"
  echo "    Matched patterns: $(grep -oE "$(IFS="|"; echo "${PATTERNS[*]}")" "$file" | tr '\n' ' ')"
  echo "    File size: $(ls -lh "$file" | awk '{print $5}')"
  echo "    Last modified: $(stat -c %y "$file" 2>/dev/null || echo 'N/A')"
  echo "    Owner: $(stat -c '%U:%G' "$file" 2>/dev/null || echo 'N/A')"
  echo "    MD5: $(md5sum "$file" 2>/dev/null | cut -d' ' -f1 || echo 'N/A')"
  echo "    First 5 lines:"
  head -n 5 "$file" | sed 's/^/    /'
  echo -e "\n---\n"
done
'''

# This template detects obfuscated PHP web shells using common patterns
