#!/usr/bin/env node

/**
 * Simplified Puppeteer Security Test Script
 * 
 * This is a streamlined version of the Puppeteer demo that's
 * designed to test basic website security with minimal dependencies.
 */

const puppeteer = require('puppeteer');
const fs = require('fs').promises;
const path = require('path');

// ANSI color codes for terminal output
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  red: "\x1b[31m"
};

async function scanWebsite(url) {
  console.log(`${colors.bright}Starting Puppeteer Quick Security Scan${colors.reset}`);
  console.log(`${colors.blue}Target:${colors.reset} ${url}\n`);
  
  // Create screenshots directory
  const screenshotDir = path.join(__dirname, 'screenshots');
  await fs.mkdir(screenshotDir, { recursive: true }).catch(() => {});

  // Launch browser with minimal dependencies
  const browser = await puppeteer.launch({
    headless: 'new',
    args: [
      '--no-sandbox', 
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage'
    ]
  });
  
  try {
    const page = await browser.newPage();
    
    // Set longer timeouts
    page.setDefaultNavigationTimeout(60000);
    page.setDefaultTimeout(60000);
    
    // Set viewport and user agent
    await page.setViewport({ width: 1280, height: 800 });
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36');
    
    // Track errors
    const errors = [];
    page.on('error', err => errors.push(`Page error: ${err.message}`));
    page.on('pageerror', err => errors.push(`JavaScript error: ${err.message}`));
    
    console.log(`${colors.yellow}Loading page...${colors.reset}`);
    
    // Navigate to page
    const response = await page.goto(url, { 
      waitUntil: 'networkidle2',
      timeout: 30000
    });
    
    // Get HTTP status
    const status = response.status();
    console.log(`${colors.green}Page loaded!${colors.reset} Status code: ${status}`);
    
    // Take screenshot
    const domain = new URL(url).hostname;
    const screenshotPath = path.join(screenshotDir, `${domain.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.png`);
    await page.screenshot({ path: screenshotPath });
    console.log(`Screenshot saved to: ${screenshotPath}`);
    
    // Get security headers
    const headers = response.headers();
    const securityHeaders = {
      'Content-Security-Policy': headers['content-security-policy'] || null,
      'Strict-Transport-Security': headers['strict-transport-security'] || null,
      'X-Content-Type-Options': headers['x-content-type-options'] || null,
      'X-Frame-Options': headers['x-frame-options'] || null,
      'X-XSS-Protection': headers['x-xss-protection'] || null,
      'Referrer-Policy': headers['referrer-policy'] || null,
      'Permissions-Policy': headers['permissions-policy'] || null
    };
    
    // Extract all links
    const links = await page.evaluate(() => {
      const anchors = Array.from(document.querySelectorAll('a'));
      return anchors.map(a => a.href);
    });
    
    // Check for forms
    const forms = await page.evaluate(() => {
      return Array.from(document.forms).map(form => ({
        action: form.action,
        method: form.method,
        secure: form.action.startsWith('https:')
      }));
    });
    
    // Check for mixed content
    const mixedContent = await page.evaluate(() => {
      const insecureElements = document.querySelectorAll('img[src^="http:"], script[src^="http:"], link[href^="http:"]');
      return Array.from(insecureElements).map(el => ({
        tag: el.tagName.toLowerCase(),
        src: el.src || el.href
      }));
    });
    
    // Output results
    console.log(`\n${colors.bright}=========== SECURITY SCAN RESULTS ===========${colors.reset}\n`);
    
    // Security headers
    console.log(`${colors.bright}Security Headers:${colors.reset}`);
    let missingHeaders = 0;
    Object.entries(securityHeaders).forEach(([name, value]) => {
      if (value) {
        console.log(`${colors.green}✓${colors.reset} ${name}: ${value.length > 50 ? value.substring(0, 50) + '...' : value}`);
      } else {
        console.log(`${colors.red}✗${colors.reset} ${name}: Missing`);
        missingHeaders++;
      }
    });
    console.log(`${missingHeaders} of 7 security headers missing\n`);
    
    // Forms security
    console.log(`${colors.bright}Forms:${colors.reset}`);
    if (forms.length === 0) {
      console.log('No forms detected on page');
    } else {
      forms.forEach((form, i) => {
        if (form.secure) {
          console.log(`${colors.green}✓${colors.reset} Form #${i+1}: Submits securely to ${form.action}`);
        } else {
          console.log(`${colors.red}✗${colors.reset} Form #${i+1}: Insecure submission to ${form.action}`);
        }
      });
    }
    console.log('');
    
    // Mixed content
    console.log(`${colors.bright}Mixed Content:${colors.reset}`);
    if (mixedContent.length === 0) {
      console.log(`${colors.green}✓${colors.reset} No mixed content detected`);
    } else {
      console.log(`${colors.red}✗${colors.reset} Found ${mixedContent.length} instances of mixed content:`);
      mixedContent.slice(0, 5).forEach(item => {
        console.log(`  - ${item.tag} from ${item.src}`);
      });
      if (mixedContent.length > 5) {
        console.log(`  ... and ${mixedContent.length - 5} more`);
      }
    }
    console.log('');
    
    // JavaScript errors
    console.log(`${colors.bright}JavaScript Errors:${colors.reset}`);
    if (errors.length === 0) {
      console.log(`${colors.green}✓${colors.reset} No JavaScript errors detected`);
    } else {
      console.log(`${colors.red}✗${colors.reset} Found ${errors.length} JavaScript errors:`);
      errors.slice(0, 5).forEach(error => {
        console.log(`  - ${error}`);
      });
      if (errors.length > 5) {
        console.log(`  ... and ${errors.length - 5} more`);
      }
    }
    console.log('');
    
    // Links
    console.log(`${colors.bright}Links:${colors.reset}`);
    const uniqueLinks = [...new Set(links.filter(link => link && link.startsWith('http')))];
    console.log(`Found ${uniqueLinks.length} unique links`);
    console.log('');
    
    // Overall rating
    let securityScore = 100;
    securityScore -= missingHeaders * 10;
    securityScore -= forms.filter(f => !f.secure).length * 15;
    securityScore -= mixedContent.length > 0 ? 20 : 0;
    securityScore = Math.max(0, Math.min(100, securityScore));
    
    let rating;
    if (securityScore >= 90) rating = `${colors.green}Excellent${colors.reset}`;
    else if (securityScore >= 70) rating = `${colors.green}Good${colors.reset}`;
    else if (securityScore >= 50) rating = `${colors.yellow}Fair${colors.reset}`;
    else rating = `${colors.red}Poor${colors.reset}`;
    
    console.log(`${colors.bright}Overall Security Rating:${colors.reset} ${rating} (${securityScore}/100)`);
    
    return {
      success: true,
      message: `Scan completed successfully!`,
      securityScore
    };
    
  } catch (error) {
    console.error(`\n${colors.red}Error during scan:${colors.reset} ${error.message}`);
    return {
      success: false,
      message: error.message
    };
  } finally {
    await browser.close();
  }
}

// Check command line arguments
const url = process.argv[2];
if (!url) {
  console.log(`
${colors.bright}Puppeteer Quick Security Scan${colors.reset}

Usage: node quick-scan.js <url>

Examples:
  node quick-scan.js https://example.com
  node quick-scan.js google.com
`);
  process.exit(1);
}

// Ensure URL has a protocol
const targetUrl = url.startsWith('http') ? url : `https://${url}`;

// Run the scan
scanWebsite(targetUrl)
  .then(result => {
    if (result.success) {
      console.log(`\n${colors.green}${colors.bright}Scan completed successfully!${colors.reset}`);
      process.exit(0);
    } else {
      console.log(`\n${colors.red}${colors.bright}Scan failed:${colors.reset} ${result.message}`);
      process.exit(1);
    }
  })
  .catch(error => {
    console.error(`\n${colors.red}${colors.bright}Unhandled error:${colors.reset} ${error.message}`);
    process.exit(1);
  });
