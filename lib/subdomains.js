/**
 * Subdomain Enumeration and Live Status Checker Module
 * Discovers subdomains using both passive sources and validates their live status
 */
const axios = require('axios');
const dns = require('dns').promises;
const chalk = require('chalk');
const ora = require('ora');

/**
 * Get subdomains from various passive sources
 * @param {string} domain - Root domain to check
 * @returns {Promise<string[]>} - Array of discovered subdomains
 */
async function getSubdomainsFromSources(domain) {
  const results = new Set();
  const spinner = ora(`Discovering subdomains for ${domain}...`).start();
  let sourcesChecked = 0;
  let totalFound = 0;

  // crt.sh (Certificate Transparency logs)
  try {
    spinner.text = `Checking crt.sh for ${domain}...`;
    const res = await axios.get(`https://crt.sh/?q=%25.${domain}&output=json`, { timeout: 10000 });
    const data = res.data;
    
    if (Array.isArray(data)) {
      data.forEach(entry => {
        if (entry.name_value) {
          entry.name_value.split('\n').forEach(s => {
            s = s.trim().toLowerCase();
            // Filter out wildcards and ensure it's a proper subdomain
            if (s.endsWith(domain) && !s.includes('*')) {
              results.add(s);
            }
          });
        }
      });
    }
    sourcesChecked++;
    spinner.text = `Found ${results.size} subdomains from crt.sh`;
  } catch (e) {
    spinner.text = `Error checking crt.sh: ${e.message}`;
  }

  // DNS Bufferover (if available, sometimes unstable)
  try {
    spinner.text = `Checking DNS Bufferover for ${domain}...`;
    const res = await axios.get(`https://dns.bufferover.run/dns?q=.${domain}`, { timeout: 8000 });
    const json = res.data;
    
    const found = json.FDNS_A || [];
    found.forEach(r => {
      const parts = r.split(',');
      if (parts[1] && parts[1].endsWith(domain)) {
        results.add(parts[1].trim().toLowerCase());
      }
    });
    sourcesChecked++;
    spinner.text = `Found ${results.size} subdomains from DNS Bufferover`;
  } catch (e) {
    // This source is often unstable, so just continue if it fails
  }

  // SecurityTrails (limited API - would need API key for real usage)
  try {
    spinner.text = `Checking alternative sources for ${domain}...`;
    // Note: This would require API key in real implementation
    // Fallback to Alienvault OTX (which doesn't require keys)
    const res = await axios.get(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`, 
      { timeout: 10000 });
    
    if (res.data && res.data.passive_dns) {
      res.data.passive_dns.forEach(record => {
        if (record.hostname && record.hostname.endsWith(domain) && !record.hostname.includes('*')) {
          results.add(record.hostname.trim().toLowerCase());
        }
      });
    }
    sourcesChecked++;
  } catch (e) {
    // Continue if this source fails
  }

  // Rapid7 FDNS dataset (public subset via Sonar API - limited without key)
  try {
    spinner.text = `Checking more sources for ${domain}...`;
    const res = await axios.get(`https://sonar.omnisint.io/subdomains/${domain}`, 
      { timeout: 15000 });
    
    if (Array.isArray(res.data)) {
      res.data.forEach(subdomain => {
        if (subdomain && subdomain.endsWith(domain)) {
          results.add(subdomain.trim().toLowerCase());
        }
      });
    }
    sourcesChecked++;
  } catch (e) {
    // Continue if this source fails
  }

  totalFound = results.size;
  spinner.succeed(`Found ${chalk.green(totalFound)} potential subdomains from ${sourcesChecked} sources`);
  
  return Array.from(results);
}

/**
 * Checks if subdomain is real by attempting DNS resolution
 * @param {string} subdomain - Subdomain to check
 * @returns {Promise<boolean>} - Whether subdomain resolves
 */
async function isRealSubdomain(subdomain) {
  try {
    // Try to resolve with ANY record type
    const records = await dns.resolve(subdomain);
    return records && records.length > 0;
  } catch (error) {
    return false;
  }
}

/**
 * Check wildcard DNS to avoid false positives
 * @param {string} domain - Base domain
 * @returns {Promise<string|null>} - Wildcard IP if exists, null otherwise
 */
async function checkWildcardDNS(domain) {
  try {
    // Generate a random subdomain that almost certainly doesn't exist
    const rand = Math.random().toString(36).substring(2, 15);
    const randomSubdomain = `${rand}-wildcard-check.${domain}`;
    
    const records = await dns.resolve(randomSubdomain);
    if (records && records.length > 0) {
      // Wildcard DNS exists, return the resolved IP
      return records[0];
    }
  } catch (error) {
    // Expected error since random subdomain shouldn't exist
  }
  return null;
}

/**
 * Checks HTTP status of a subdomain on both HTTP and HTTPS
 * @param {string} subdomain - Subdomain to check
 * @returns {Promise<object|null>} - Status info or null if unreachable
 */
async function getHttpStatus(subdomain) {
  const protocols = ['https', 'http'];
  
  for (const protocol of protocols) {
    try {
      const url = `${protocol}://${subdomain}`;
      const res = await axios.head(url, { 
        timeout: 5000, 
        maxRedirects: 5,
        validateStatus: () => true, // Don't throw on any status code
        headers: {
          'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
        }
      });
      
      if ([200, 201, 301, 302, 307, 308].includes(res.status)) {
        const redirectURL = res.headers.location || url;
        const finalURL = redirectURL.startsWith('http') ? redirectURL : `${protocol}://${subdomain}${redirectURL}`;
        
        return { 
          url: finalURL,
          status: res.status,
          protocol,
          ip: null, // Will be populated later
          server: res.headers['server'] || null,
          contentType: res.headers['content-type'] || null
        };
      }
    } catch (e) {
      // Try next protocol
    }
  }
  
  return null;
}

/**
 * Get IP address for a subdomain
 * @param {string} subdomain - Subdomain to resolve
 * @returns {Promise<string|null>} - IP address or null
 */
async function getIPAddress(subdomain) {
  try {
    const records = await dns.resolve4(subdomain);
    return records[0] || null;
  } catch (error) {
    return null;
  }
}

/**
 * Gets CNAME record for a subdomain if available
 * @param {string} subdomain - Subdomain to check
 * @returns {Promise<string|null>} - CNAME or null
 */
async function getCNAME(subdomain) {
  try {
    const records = await dns.resolveCname(subdomain);
    return records[0] || null;
  } catch (error) {
    return null;
  }
}

/**
 * Find live subdomains for a given domain
 * @param {string} domain - Domain to enumerate subdomains for
 * @param {Object} options - Options for the scan
 * @returns {Promise<Array>} - List of verified live subdomains with status info
 */
async function findLiveSubdomains(domain, options = {}) {
  const startTime = Date.now();
  const candidates = await getSubdomainsFromSources(domain);
  
  if (candidates.length === 0) {
    return [];
  }
  
  // Check for wildcard DNS to avoid false positives
  const wildcardIP = await checkWildcardDNS(domain);
  if (wildcardIP) {
    console.log(chalk.yellow(`⚠️  Wildcard DNS detected for ${domain} (resolves to ${wildcardIP})`));
  }
  
  // Status tracking
  const total = candidates.length;
  let processed = 0;
  
  const spinner = ora(`Validating ${total} subdomains...`).start();
  
  // Use a limited concurrency queue for DNS lookups
  const BATCH_SIZE = 10;
  const results = [];
  
  // Process in batches to manage concurrency
  for (let i = 0; i < candidates.length; i += BATCH_SIZE) {
    const batch = candidates.slice(i, i + BATCH_SIZE);
    
    const batchResults = await Promise.all(
      batch.map(async (subdomain) => {
        // Skip the main domain itself if it's in the results
        if (subdomain === domain) {
          processed++;
          spinner.text = `Validating subdomains: ${processed}/${total}`;
          return null;
        }
        
        // First check if DNS resolves
        if (!(await isRealSubdomain(subdomain))) {
          processed++;
          spinner.text = `Validating subdomains: ${processed}/${total}`;
          return null;
        }
        
        // Get IP address for clustering
        const ip = await getIPAddress(subdomain);
        
        // Skip if it resolves to the wildcard IP
        if (wildcardIP && ip === wildcardIP) {
          processed++;
          spinner.text = `Validating subdomains: ${processed}/${total}`;
          return null;
        }
        
        // Perform HTTP status check
        const statusInfo = await getHttpStatus(subdomain);
        
        // Get CNAME if available (for CNAME cloaking detection)
        const cname = await getCNAME(subdomain);
        
        processed++;
        spinner.text = `Validating subdomains: ${processed}/${total} (found ${results.length} live)`;
        
        if (statusInfo) {
          return {
            subdomain,
            ...statusInfo,
            ip,
            cname
          };
        }
        
        return null;
      })
    );
    
    // Add valid results from this batch
    results.push(...batchResults.filter(Boolean));
  }
  
  const duration = (Date.now() - startTime) / 1000;
  spinner.succeed(`Found ${chalk.green(results.length)} live subdomains in ${duration.toFixed(1)}s`);
  
  return results;
}

/**
 * Format subdomain scan results for display
 * @param {Array} results - Subdomain scan results
 * @param {string} domain - Base domain
 * @returns {string} - Formatted results string
 */
function formatSubdomainResults(results, domain) {
  if (results.length === 0) {
    return chalk.yellow(`\nNo live subdomains found for ${domain}\n`);
  }

  let output = `\n${chalk.blue('🔍 Live Subdomains for')} ${chalk.green(domain)}:\n\n`;
  
  // Group by status codes for better organization
  const grouped = {};
  results.forEach(r => {
    const key = r.status.toString();
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(r);
  });
  
  // Sort by status code
  const statusOrder = ['200', '201', '301', '302', '307', '308'];
  const sortedKeys = Object.keys(grouped).sort((a, b) => {
    return statusOrder.indexOf(a) - statusOrder.indexOf(b);
  });
  
  sortedKeys.forEach(status => {
    const items = grouped[status];
    let statusColor;
    
    // Color-code based on status
    if (status.startsWith('2')) {
      statusColor = chalk.green;
    } else if (status.startsWith('3')) {
      statusColor = chalk.yellow;
    } else {
      statusColor = chalk.gray;
    }
    
    items.forEach(r => {
      output += chalk.green(`✅ ${r.subdomain}`) + 
                ` → ${chalk.cyan(r.protocol + '://' + r.subdomain)}` + 
                ` [${statusColor(r.status)}]`;
      
      if (r.server) {
        output += chalk.gray(` (Server: ${r.server})`);
      }
      
      if (r.cname) {
        output += chalk.yellow(` (CNAME: ${r.cname})`);
      }
      
      output += '\n';
    });
  });
  
  // Add summary
  output += `\n${chalk.blue('Total:')} ${chalk.green(results.length)} live subdomains\n`;
  
  return output;
}

module.exports = {
  findLiveSubdomains,
  getSubdomainsFromSources,
  formatSubdomainResults,
  isRealSubdomain,
  getHttpStatus
};
