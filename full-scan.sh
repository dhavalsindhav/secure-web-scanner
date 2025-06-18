#!/bin/bash
# Full security scan with all checks enabled
# Usage: ./full-scan.sh example.com

if [ -z "$1" ]; then
  echo "Usage: $0 <target-domain>"
  echo "Example: $0 example.com"
  exit 1
fi

TARGET="$1"
OUTPUT_FILE="${TARGET//./_}_full_scan_$(date +%Y%m%d_%H%M%S).json"

echo "Starting comprehensive security scan of $TARGET"
echo "This will run all available security checks"
echo "Results will be saved to $OUTPUT_FILE"

node ./bin/cli.js "$TARGET" \
  --advanced \
  --puppeteer \
  --screenshot \
  --client-side-vulns \
  --extract-links \
  --content-security \
  --dns \
  --whois \
  --ports \
  --port-level comprehensive \
  --fingerprint \
  --vulnerabilities \
  --output "$OUTPUT_FILE" \
  --format json

echo "Scan complete! Full results saved to $OUTPUT_FILE"
echo "Quick summary also displayed above"
