/**
 * Reconnaissance module for OSINT gathering
 * This module provides functionality for:
 * - IP and domain reconnaissance
 * - Email harvesting
 * - DNS record enumeration
 * - Certificate transparency checks
 * - ASN and network range discovery
 */

const axios = require('axios');
const { getWhoisInfo, extractDomainInfo } = require('./whois');
const { checkDns } = require('./dns');
const { promises: dns } = require('dns');

/**
 * Perform reconnaissance on a target domain or IP
 * @param {string} target - Domain or IP to gather information about
 * @param {object} options - Recon options
 * @returns {Promise<object>} - Reconnaissance results
 */
async function performRecon(target, options = {}) {
  // Default options
  const defaultOptions = {
    whois: true,        // Perform WHOIS lookup
    dns: true,          // Perform DNS enumeration
    emails: true,       // Perform email harvesting
    certificates: true, // Check certificate transparency logs
    asn: true,          // Perform ASN lookup
    social: false       // Check for social media presence
  };

  const reconOptions = { ...defaultOptions, ...options };
  const results = {
    target,
    timestamp: new Date().toISOString(),
    targetType: isIpAddress(target) ? 'ip' : 'domain',
    whois: null,
    dns: null,
    ip: null,
    asn: null,
    emails: null,
    certificates: null,
    social: null
  };

  // Run the requested reconnaissance methods
  const promises = [];

  // IP resolution (for domains)
  if (results.targetType === 'domain') {
    promises.push(
      resolveIp(target).then(ipInfo => {
        results.ip = ipInfo;
      }).catch(err => {
        results.ip = { error: err.message };
      })
    );
  }

  // WHOIS information
  if (reconOptions.whois) {
    promises.push(
      getWhoisInfo(target).then(whoisInfo => {
        results.whois = {
          raw: whoisInfo,
          parsed: extractDomainInfo(whoisInfo)
        };
      }).catch(err => {
        results.whois = { error: err.message };
      })
    );
  }

  // DNS enumeration
  if (reconOptions.dns) {
    promises.push(
      checkDns(target).then(dnsInfo => {
        results.dns = dnsInfo;
      }).catch(err => {
        results.dns = { error: err.message };
      })
    );
  }

  // ASN lookup
  if (reconOptions.asn) {
    promises.push(
      performAsnLookup(target).then(asnInfo => {
        results.asn = asnInfo;
      }).catch(err => {
        results.asn = { error: err.message };
      })
    );
  }

  // Email harvesting
  if (reconOptions.emails) {
    promises.push(
      harvestEmails(target).then(emailInfo => {
        results.emails = emailInfo;
      }).catch(err => {
        results.emails = { error: err.message };
      })
    );
  }

  // Certificate transparency check
  if (reconOptions.certificates) {
    promises.push(
      checkCertificateTransparency(target).then(certInfo => {
        results.certificates = certInfo;
      }).catch(err => {
        results.certificates = { error: err.message };
      })
    );
  }

  // Social media reconnaissance
  if (reconOptions.social) {
    promises.push(
      checkSocialMedia(target).then(socialInfo => {
        results.social = socialInfo;
      }).catch(err => {
        results.social = { error: err.message };
      })
    );
  }

  // Wait for all reconnaissance tasks to complete
  await Promise.allSettled(promises);

  return results;
}

/**
 * Check if a string is an IP address
 * @param {string} str - String to check
 * @returns {boolean} - True if IP address
 */
function isIpAddress(str) {
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(str);
}

/**
 * Resolve domain to IP address
 * @param {string} domain - Domain to resolve
 * @returns {Promise<object>} - IP resolution info
 */
async function resolveIp(domain) {
  try {
    const addresses = await dns.resolve4(domain);
    const addressesV6 = await dns.resolve6(domain).catch(() => []);
    
    return {
      ipv4: addresses,
      ipv6: addressesV6
    };
  } catch (error) {
    throw new Error(`Failed to resolve IP: ${error.message}`);
  }
}

/**
 * Perform ASN lookup for an IP or domain
 * @param {string} target - IP or domain
 * @returns {Promise<object>} - ASN information
 */
async function performAsnLookup(target) {
  let ip = target;
  
  // If target is a domain, resolve to IP first
  if (!isIpAddress(target)) {
    try {
      const ipInfo = await resolveIp(target);
      ip = ipInfo.ipv4[0]; // Use first IPv4 address
    } catch (error) {
      throw new Error(`Failed to resolve domain for ASN lookup: ${error.message}`);
    }
  }
  
  try {
    // Use ipinfo.io to get ASN information
    const response = await axios.get(`https://ipinfo.io/${ip}/json`);
    const data = response.data;
    
    return {
      ip,
      asn: data.org ? data.org.split(' ')[0] : null, // Extract ASN number
      organization: data.org ? data.org.substring(data.org.indexOf(' ') + 1) : null,
      country: data.country || null,
      region: data.region || null,
      city: data.city || null,
      loc: data.loc || null,
      postal: data.postal || null,
      timezone: data.timezone || null
    };
  } catch (error) {
    throw new Error(`ASN lookup failed: ${error.message}`);
  }
}

/**
 * Harvest email addresses associated with a domain
 * @param {string} domain - Domain to search for emails
 * @returns {Promise<object>} - Email harvesting results
 */
async function harvestEmails(domain) {
  // This is a placeholder function
  // In a real implementation, you would:
  // 1. Check WHOIS data for emails
  // 2. Search DNS for MX records
  // 3. Use APIs like Hunter.io (with API key)
  // 4. Optionally scrape website content (ethically and legally)
  
  // For demo purposes, we'll return mock data
  return {
    found: false,
    source: "Mock data - email harvesting requires API integration",
    emails: []
  };
}

/**
 * Check certificate transparency logs for a domain
 * @param {string} domain - Domain to check
 * @returns {Promise<object>} - Certificate information
 */
async function checkCertificateTransparency(domain) {
  try {
    // Use crt.sh API to check certificate transparency logs
    const response = await axios.get(`https://crt.sh/?q=${domain}&output=json`);
    
    if (!Array.isArray(response.data)) {
      return {
        found: false,
        certificates: []
      };
    }
    
    // Process and deduplicate certificates
    const uniqueCerts = new Map();
    response.data.forEach(cert => {
      const key = `${cert.id}-${cert.not_before}-${cert.not_after}`;
      if (!uniqueCerts.has(key)) {
        uniqueCerts.set(key, {
          id: cert.id,
          issuer: cert.issuer_name,
          subject: cert.name_value,
          validFrom: cert.not_before,
          validTo: cert.not_after
        });
      }
    });
    
    return {
      found: uniqueCerts.size > 0,
      count: uniqueCerts.size,
      certificates: Array.from(uniqueCerts.values())
    };
  } catch (error) {
    throw new Error(`Certificate transparency check failed: ${error.message}`);
  }
}

/**
 * Check for social media presence
 * @param {string} domain - Domain to check
 * @returns {Promise<object>} - Social media information
 */
async function checkSocialMedia(domain) {
  // Extract company name from domain
  const companyName = domain.split('.')[0];
  
  // This is a placeholder function
  // In a real implementation, you would:
  // 1. Check common social media platforms for company presence
  // 2. Use APIs where available
  // 3. Use search engines with site: operators
  
  // For demo purposes, we'll return mock data
  return {
    note: "Social media checking requires API keys for platforms",
    platforms: [
      {
        platform: "LinkedIn",
        found: false,
        url: null
      },
      {
        platform: "Twitter",
        found: false,
        url: null
      },
      {
        platform: "Facebook",
        found: false,
        url: null
      },
      {
        platform: "Instagram",
        found: false,
        url: null
      }
    ]
  };
}

module.exports = {
  performRecon,
  resolveIp,
  performAsnLookup,
  checkCertificateTransparency
};
