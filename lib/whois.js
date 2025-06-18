const { safeRequire, isBrowser, createUnavailableFeatureProxy } = require('./browser-compatibility');
const whoisJson = safeRequire('whois-json', createUnavailableFeatureProxy('whois-json'));

/**
 * Get WHOIS information for a domain
 * @param {string} domain - The domain to check (without protocol)
 * @returns {Promise<object>} - WHOIS data
 */
async function getWhoisInfo(domain) {
  // Remove protocol and path if present
  domain = domain.replace(/^https?:\/\//i, '').split('/')[0];
  
  try {
    const results = await whoisJson(domain);
    return {
      domain,
      whoisData: results,
      error: false
    };
  } catch (err) {
    return {
      domain,
      error: true,
      message: err.message
    };
  }
}

/**
 * Extract relevant domain information from WHOIS data
 * @param {object} whoisData - Raw WHOIS data from getWhoisInfo
 * @returns {object} - Simplified domain information
 */
function extractDomainInfo(whoisData) {
  if (whoisData.error) {
    return {
      error: true,
      message: whoisData.message
    };
  }
  
  const data = whoisData.whoisData;
  
  // Initialize with common field names that might be in WHOIS data
  // Different registrars use different field names
  let registrar = data.registrar || data.Registrar || data['Registrar:'] || null;
  let creationDate = data.creationDate || 
                   data.created || 
                   data['Creation Date'] || 
                   data['Registration Date'] || 
                   null;
  let expiryDate = data.expiryDate || 
                  data.expires || 
                  data['Expiration Date'] || 
                  data['Registry Expiry Date'] || 
                  null;
  let nameServers = data.nameServers || 
                   data['Name Server'] || 
                   data['Nameservers'] || 
                   null;
  
  // If nameServers is an array, join it
  if (Array.isArray(nameServers)) {
    nameServers = nameServers.join(', ');
  }
  
  return {
    domain: whoisData.domain,
    registrar,
    creationDate,
    expiryDate,
    nameServers,
    rawData: data // Include raw data for advanced use
  };
}

module.exports = { getWhoisInfo, extractDomainInfo };
