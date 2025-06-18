#!/usr/bin/env node
/**
 * Puppeteer-based Security Scanner Demo
 * 
 * This script demonstrates the advanced scanning capabilities
 * added by Puppeteer integration in secure-web-scanner.
 */

const { scan } = require('./lib/index');
const fs = require('fs').promises;
const path = require('path');

// ANSI color codes for terminal output
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  red: "\x1b[31m"
};

// Example script to demonstrate Puppeteer-based scanning
async function runPuppeteerDemo() {
  console.log(`${colors.bright}Starting Puppeteer-based security scan demo...${colors.reset}\n`);

  // Create screenshots directory if it doesn't exist
  const screenshotDir = path.join(__dirname, 'screenshots');
  await fs.mkdir(screenshotDir, { recursive: true }).catch(err => {
    console.warn(`Warning: Could not create screenshots directory: ${err.message}`);
  });
  
  // Get target from command line or use default
  let target = process.argv[2] || 'https://example.com';
  
  // Ensure target has a protocol
  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    target = 'https://' + target;
  }
  
  console.log(`${colors.blue}Target:${colors.reset} ${target}\n`);
  
  // Test URL validity
  try {
    new URL(target);
  } catch (e) {
    console.error(`${colors.red}Error:${colors.reset} Invalid URL: ${target}`);
    process.exit(1);
  }

  try {
    console.log(`${colors.yellow}Running scan with Puppeteer features enabled...${colors.reset}`);
    
    // Generate screenshot filename based on target domain
    const domain = new URL(target.startsWith('http') ? target : `https://${target}`).hostname;
    const screenshotPath = path.join(screenshotDir, `${domain.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.png`);
    
    // Run scan with Puppeteer features enabled
    const results = await scan(target, {
      // Basic scan options
      checkSSL: true,
      checkHeaders: true,
      detectTech: true,
      
      // Enable Puppeteer
      usePuppeteer: true,
      puppeteerOptions: {
        takeScreenshot: true,
        screenshotPath: screenshotPath,
        scanClientSideVulns: true,
        extractLinks: true,
        contentSecurityAnalysis: true,
        saveArtifacts: true
      }
    });

    // Display Puppeteer results
    if (results.puppeteer) {
      console.log('\n=== Puppeteer-Based Scanning Results ===\n');

      // Display screenshot path if available
      if (results.puppeteer.screenshot) {
        console.log(`Screenshot saved to: ${results.puppeteer.screenshot.path}`);
      }

      // Display vulnerability findings
      if (results.puppeteer.vulnerabilities) {
        const vulnResults = results.puppeteer.vulnerabilities;
        
        console.log('\n== Client-Side Security Analysis ==\n');
        console.log(`Risk Score: ${vulnResults.riskScore ? vulnResults.riskScore.score : 'N/A'}/100 (${vulnResults.riskScore ? vulnResults.riskScore.riskLevel : 'N/A'})`);
        
        // Display detected libraries
        if (vulnResults.clientSideSecurity && vulnResults.clientSideSecurity.detectedLibraries) {
          console.log('\nDetected JavaScript Libraries:');
          vulnResults.clientSideSecurity.detectedLibraries.forEach(lib => {
            console.log(`- ${lib}`);
          });
        }

        // Display security headers
        if (vulnResults.securityHeaders) {
          console.log('\nSecurity Headers:');
          console.log(`Score: ${vulnResults.securityHeaders.securityScore}/100`);
          console.log(`Present Headers: ${vulnResults.securityHeaders.securityHeaderCount}/${vulnResults.securityHeaders.presentHeaders.length + vulnResults.securityHeaders.missingHeaders.length}`);
          
          if (vulnResults.securityHeaders.missingHeaders.length > 0) {
            console.log('\nMissing Security Headers:');
            vulnResults.securityHeaders.missingHeaders.forEach(header => {
              console.log(`- ${header.name} (${header.severity}): ${header.recommendation}`);
            });
          }
        }

        // Display vulnerabilities
        if (vulnResults.vulnerabilities && vulnResults.vulnerabilities.length > 0) {
          console.log('\nVulnerabilities Found:');
          vulnResults.vulnerabilities.forEach(vuln => {
            console.log(`\n- Type: ${vuln.type} (${vuln.severity})`);
            console.log(`  Description: ${vuln.description}`);
            if (vuln.evidence) console.log(`  Evidence: ${vuln.evidence}`);
            console.log(`  Remediation: ${vuln.remediation}`);
          });
        } else {
          console.log('\nNo client-side vulnerabilities detected');
        }
      }

      // Display extracted links
      if (results.puppeteer.links && results.puppeteer.links.length > 0) {
        console.log('\n== Extracted Links ==\n');
        console.log(`Found ${results.puppeteer.links.length} links on the page:`);
        results.puppeteer.links.slice(0, 10).forEach((link, i) => {
          console.log(`${i+1}. ${link}`);
        });
        
        if (results.puppeteer.links.length > 10) {
          console.log(`... and ${results.puppeteer.links.length - 10} more`);
        }
      }

      // Display content security info
      if (results.puppeteer.contentSecurity) {
        const contentSecurity = results.puppeteer.contentSecurity;
        console.log('\n== Content Security Analysis ==\n');
        console.log(`Third-party domains: ${contentSecurity.thirdPartyCount}`);
        
        if (contentSecurity.iframeAnalysis) {
          console.log(`\nIframes: ${contentSecurity.iframeAnalysis.count}`);
          console.log(`Sandboxed iframes: ${contentSecurity.iframeAnalysis.hasSandboxedIframes ? 'Yes' : 'No'}`);
          console.log(`Security risk from iframe configuration: ${contentSecurity.iframeAnalysis.securityRisk ? 'Yes' : 'No'}`);
        }
      }
    } else {
      console.log('No Puppeteer-based results available. Make sure Puppeteer is installed and usePuppeteer option is enabled.');
    }
  } catch (error) {
    console.error(`\n${colors.red}Error during demo scan:${colors.reset} ${error.message}`);
    
    // Check for common errors and provide helpful messages
    if (error.message.includes('puppeteer')) {
      console.error(`\n${colors.yellow}This could be a Puppeteer installation issue.${colors.reset}`);
      console.error(`Try running: ${colors.bright}./test-puppeteer.sh${colors.reset} to diagnose the problem.`);
    } else if (error.message.includes('ERR_NAME_NOT_RESOLVED')) {
      console.error(`\n${colors.yellow}The target domain could not be resolved.${colors.reset}`);
      console.error(`Check your internet connection or try a different domain.`);
    } else if (error.message.includes('timeout')) {
      console.error(`\n${colors.yellow}The scan timed out.${colors.reset}`);
      console.error(`The target site might be slow or unresponsive.`);
    }
    
    // Only show stack trace if we're in debug mode
    if (process.env.DEBUG && error.stack) {
      console.error(`\n${colors.dim}Stack trace:${colors.reset}\n${error.stack}`);
    }
    
    process.exit(1);
  }
}

// Show help if requested
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log(`
${colors.bright}Puppeteer-based Security Scanner Demo${colors.reset}

Usage: ${colors.bright}node puppeteer-demo.js [target]${colors.reset}

Arguments:
  target    The website to scan (default: https://example.com)

Examples:
  ${colors.dim}# Scan the default example site${colors.reset}
  node puppeteer-demo.js
  
  ${colors.dim}# Scan a specific website${colors.reset}
  node puppeteer-demo.js https://github.com

  ${colors.dim}# Enable debug output${colors.reset}
  DEBUG=true node puppeteer-demo.js
  `);
  process.exit(0);
}

// Run the demo
runPuppeteerDemo().catch(error => {
  console.error(`\n${colors.red}Unhandled error:${colors.reset} ${error.message}`);
  process.exit(1);
});
