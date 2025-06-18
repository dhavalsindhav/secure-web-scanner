#!/bin/bash
# Helper script for secure-web-scanner with Puppeteer support

# Color codes
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BOLD="\033[1m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Display help message
function show_help {
  echo -e "${BOLD}secure-web-scanner${RESET} - Web Security Scanner with Puppeteer"
  echo ""
  echo "Usage: $(basename "$0") [command] [options]"
  echo ""
  echo "Commands:"
  echo "  scan <target>          Scan a target website"
  echo "  quick <target>         Run quick security scan (faster, more reliable)"
  echo "  demo [target]          Run the Puppeteer demo"
  echo "  test                   Test the Puppeteer installation"
  echo "  help                   Show this help message"
  echo ""
  echo "Scan options:"
  echo "  --puppeteer            Enable all Puppeteer features"
  echo "  --screenshot           Capture screenshot"
  echo "  --client-side-vulns    Scan for client-side vulnerabilities"
  echo "  --extract-links        Extract links from the page"
  echo "  --advanced             Enable all advanced features"
  echo ""
  echo "Examples:"
  echo "  ./run.sh scan example.com --puppeteer"
  echo "  ./run.sh demo github.com"
  echo "  ./run.sh test"
}

# Check command
case "$1" in
  scan)
    if [ -z "$2" ]; then
      echo -e "${RED}Error: No target specified${RESET}"
      echo "Usage: $0 scan <target> [options]"
      exit 1
    fi
    echo -e "${BLUE}Scanning target:${RESET} $2"
    shift
    ./bin/cli.js "$@"
    ;;
    
  quick)
    if [ -z "$2" ]; then
      echo -e "${RED}Error: No target specified${RESET}"
      echo "Usage: $0 quick <target>"
      exit 1
    fi
    echo -e "${BLUE}Running quick scan on:${RESET} $2"
    node quick-scan.js "$2"
    ;;
    
  demo)
    target="$2"
    if [ -z "$target" ]; then
      target="https://example.com"
    fi
    echo -e "${BLUE}Running Puppeteer demo on:${RESET} $target"
    node puppeteer-demo.js "$target"
    ;;
    
  test)
    echo -e "${BLUE}Testing Puppeteer installation...${RESET}"
    ./test-puppeteer.sh
    ;;
    
  help|--help|-h)
    show_help
    ;;
    
  *)
    if [ -z "$1" ]; then
      show_help
    else
      echo -e "${RED}Unknown command:${RESET} $1"
      echo "Run '$0 help' for usage information"
      exit 1
    fi
    ;;
esac
