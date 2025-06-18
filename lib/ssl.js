const sslChecker = require('ssl-checker');
const { isIP } = require('net');

/**
 * Get SSL certificate information for a domain
 * @param {string} domain - The domain to check (without protocol)
 * @returns {Promise<object>} - SSL certificate details
 */
async function getSSLInfo(domain) {
  if (isIP(domain)) {
    return { error: 'Cannot check SSL for an IP address' };
  }
  
  try {
    return await sslChecker(domain, { method: "GET", port: 443 });
  } catch (error) {
    return { 
      error: true,
      message: error.message,
      valid: false
    };
  }
}

/**
 * Check for common SSL/TLS issues
 * @param {object} sslInfo - SSL certificate info from getSSLInfo
 * @returns {object} - Security assessment
 */
function analyzeSSL(sslInfo) {
  if (sslInfo.error) {
    return {
      status: 'error',
      issues: ['Unable to retrieve SSL information']
    };
  }

  const issues = [];
  const warnings = [];
  
  // Check days until expiration
  if (sslInfo.daysRemaining < 30) {
    issues.push(`Certificate expires soon (${sslInfo.daysRemaining} days remaining)`);
  } else if (sslInfo.daysRemaining < 90) {
    warnings.push(`Certificate expires in ${sslInfo.daysRemaining} days`);
  }
  
  // Check if valid
  if (!sslInfo.valid) {
    issues.push('Certificate is not valid');
  }

  return {
    status: issues.length > 0 ? 'issues' : warnings.length > 0 ? 'warnings' : 'secure',
    issues,
    warnings
  };
}

module.exports = { getSSLInfo, analyzeSSL };
