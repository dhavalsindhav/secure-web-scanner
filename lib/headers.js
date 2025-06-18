const axios = require('axios');

/**
 * Check HTTP headers for a given URL
 * @param {string} url - The URL to check
 * @returns {Promise<object>} - HTTP headers
 */
async function checkHeaders(url) {
  // Ensure URL has a protocol
  if (!url.startsWith('http')) {
    url = 'https://' + url;
  }
  
  try {
    const response = await axios.get(url, {
      timeout: 10000,
      maxRedirects: 5,
      validateStatus: null, // Accept all status codes
      headers: {
        'User-Agent': 'secure-web-scanner/1.0.1 (https://github.com/dhavalsindhav/secure-web-scanner)'
      }
    });
    return {
      headers: response.headers,
      status: response.status,
      statusText: response.statusText
    };
  } catch (err) {
    return { 
      error: true,
      message: err.message 
    };
  }
}

/**
 * Analyze security headers
 * @param {object} headerData - Headers object from checkHeaders
 * @returns {object} - Security assessment
 */
function analyzeHeaders(headerData) {
  if (headerData.error) {
    return {
      status: 'error',
      message: headerData.message,
      issues: [],
      warnings: []
    };
  }

  const headers = headerData.headers;
  const issues = [];
  const warnings = [];

  // Essential security headers to check
  const securityHeaders = {
    'strict-transport-security': {
      present: false,
      recommendation: 'Add Strict-Transport-Security header (HSTS)'
    },
    'content-security-policy': {
      present: false,
      recommendation: 'Add Content-Security-Policy header'
    },
    'x-content-type-options': {
      present: false,
      recommendation: 'Add X-Content-Type-Options: nosniff'
    },
    'x-frame-options': {
      present: false,
      recommendation: 'Add X-Frame-Options header to prevent clickjacking'
    },
    'x-xss-protection': {
      present: false,
      recommendation: 'Add X-XSS-Protection header'
    }
  };

  // Normalize header names (lowercase)
  const normalizedHeaders = {};
  for (const key in headers) {
    normalizedHeaders[key.toLowerCase()] = headers[key];
  }

  // Check for security headers
  for (const header in securityHeaders) {
    if (normalizedHeaders[header]) {
      securityHeaders[header].present = true;
      securityHeaders[header].value = normalizedHeaders[header];
    } else {
      warnings.push(securityHeaders[header].recommendation);
    }
  }

  // Check for server disclosure
  if (normalizedHeaders['server']) {
    const serverHeader = normalizedHeaders['server'];
    // If server header reveals detailed version info
    if (/[0-9]/.test(serverHeader)) {
      issues.push('Server header reveals version information');
    } else {
      warnings.push('Server header reveals software information');
    }
  }

  return {
    status: issues.length > 0 ? 'issues' : warnings.length > 0 ? 'warnings' : 'secure',
    issues,
    warnings,
    headerDetails: securityHeaders
  };
}

module.exports = { checkHeaders, analyzeHeaders };
