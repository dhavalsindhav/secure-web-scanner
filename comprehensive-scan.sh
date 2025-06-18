#!/bin/bash
# Comprehensive Security Scan Script
# Runs a full scan with all advanced features enabled

# Check if a target is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_domain_or_url>"
    exit 1
fi

TARGET=$1
OUTPUT_DIR="./reports/$(echo $TARGET | sed 's/[^a-zA-Z0-9]/_/g')-$(date +%Y%m%d-%H%M%S)"
REPORT_FILE="$OUTPUT_DIR/comprehensive-report.json"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "🔍 Starting comprehensive security scan for $TARGET"
echo "📁 Results will be saved to $OUTPUT_DIR"

# Run the comprehensive scan
node ./bin/cli.js scan "$TARGET" \
    --advanced \
    --ai-scan \
    --api-scan \
    --auth-scan \
    --cloud-scan \
    --deps-scan \
    --puppeteer \
    --client-side-vulns \
    --extract-links \
    --content-security \
    --screenshot \
    --screenshot-path "$OUTPUT_DIR/screenshot.png" \
    --save-artifacts \
    --report-format "json,html,pdf" \
    --output "$REPORT_FILE" \
    --interactive-dashboard

# Keep this script running until user presses Ctrl+C (to keep dashboard alive)
echo "Press Ctrl+C to stop the dashboard server and exit."
wait
