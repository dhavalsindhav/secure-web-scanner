#!/bin/bash
# Script to verify Puppeteer installation and functionality

# Text styling
GREEN="\033[0;32m"
RED="\033[0;31m"
BOLD="\033[1m"
RESET="\033[0m"

echo -e "${BOLD}=== secure-web-scanner Puppeteer Installation Test ===${RESET}"
echo ""

# Check if puppeteer is installed
echo "Checking for Puppeteer installation..."
if npm list puppeteer | grep -q puppeteer; then
  echo -e "${GREEN}✓${RESET} Puppeteer is installed"
else
  echo -e "${RED}✗${RESET} Puppeteer is not installed. Installing now..."
  npm install --save puppeteer

# Check for Chromium installation
echo ""
echo "Verifying Chromium installation..."
node -e "
const puppeteer = require('puppeteer');
(async () => {
  try {
    // Launch browser with explicit headless option
    const browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage'
      ]
    });
    
    console.log('\x1b[32m✓\x1b[0m Successfully launched Chromium');
    const version = await browser.version();
    console.log('\x1b[32m✓\x1b[0m Chrome version:', version);
    
    // Test basic page navigation
    const page = await browser.newPage();
    await page.goto('about:blank');
    console.log('\x1b[32m✓\x1b[0m Page navigation successful');
    
    await browser.close();
    process.exit(0);
  } catch (err) {
    console.log('\x1b[31m✗\x1b[0m Error launching Chromium:', err.message);
    process.exit(1);
  }
})();
"

# Check if the previous command succeeded
if [ $? -eq 0 ]; then
  echo ""
  echo -e "${GREEN}${BOLD}✓ Puppeteer installation verified successfully${RESET}"
  echo ""
  echo "You can run a demo scan with: ${BOLD}node puppeteer-demo.js${RESET}"
  echo "Or use the CLI with: ${BOLD}./bin/cli.js example.com --puppeteer${RESET}"
  
  # Verify that the demo script exists
  if [ -f "./puppeteer-demo.js" ]; then
    echo -e "${GREEN}✓${RESET} Demo script is available"
  else
    echo -e "${RED}✗${RESET} Demo script not found. Please check your installation."
  fi
else
  echo ""
  echo -e "${RED}${BOLD}✗ There was a problem with the Puppeteer installation.${RESET}"
  echo ""
  echo "Common solutions:"
  echo "1. Try running: ${BOLD}npm rebuild puppeteer${RESET}"
  echo "2. Check for missing dependencies with: ${BOLD}ldd \$(which node)${RESET}"
  echo "3. If using Docker, ensure browser dependencies are installed"
  exit 1
fi

# Final check for the browser module
echo ""
echo "Validating browser.js module..."
if [ -f "./lib/browser.js" ]; then
  echo -e "${GREEN}✓${RESET} browser.js module exists"
else
  echo -e "${RED}✗${RESET} browser.js module not found. Your installation may be incomplete."
  exit 1
fi

echo ""
echo -e "${BOLD}All checks completed.${RESET}"
