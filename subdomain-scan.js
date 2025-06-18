#!/usr/bin/env node

/**
 * Subdomain Scanner CLI
 * A simple standalone script to run the subdomain enumeration and live status checker
 */

const { findLiveSubdomains, formatSubdomainResults } = require('./lib/subdomains');
const chalk = require('chalk');

// Get domain from command line arguments
const domain = process.argv[2];

if (!domain) {
  console.log(chalk.red('❌ Error: Please provide a domain name'));
  console.log(`Usage: node ${require('path').basename(__filename)} <domain>`);
  process.exit(1);
}

console.log(chalk.blue('\n🔍 Subdomain Enumeration Tool'));
console.log(chalk.blue('═════════════════════════\n'));
console.log(chalk.gray(`Target: ${domain}\n`));

// Run the scanner
(async () => {
  try {
    const results = await findLiveSubdomains(domain);
    console.log(formatSubdomainResults(results, domain));
  } catch (error) {
    console.error(chalk.red(`Error: ${error.message}`));
    if (error.stack) {
      console.error(chalk.gray(error.stack));
    }
    process.exit(1);
  }
})();
