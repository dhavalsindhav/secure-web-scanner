/**
 * CMS vulnerability scanning functionality
 * This module provides specialized scanning for common CMS platforms:
 * - WordPress
 * - Joomla
 * - Drupal
 * - Magento
 * - Others
 */

const axios = require('axios');
const cheerio = require('cheerio');
const path = require('path');
const fs = require('fs').promises;

// CMS fingerprinting patterns
const CMS_PATTERNS = {
  wordpress: {
    paths: ['/wp-login.php', '/wp-admin/', '/wp-content/'],
    headers: { 'x-powered-by': /wordpress/i },
    content: [
      { selector: 'meta[name="generator"]', attribute: 'content', pattern: /WordPress/i },
      { selector: 'link, script', attribute: 'href,src', pattern: /wp-content|wp-includes/i }
    ]
  },
  joomla: {
    paths: ['/administrator/', '/components/', '/modules/'],
    headers: { 'x-powered-by': /joomla/i },
    content: [
      { selector: 'meta[name="generator"]', attribute: 'content', pattern: /Joomla/i },
      { selector: 'script', attribute: 'src', pattern: /\/media\/jui\//i }
    ]
  },
  drupal: {
    paths: ['/admin/', '/sites/default/', '/node/'],
    headers: { 'x-generator': /Drupal/i },
    content: [
      { selector: 'meta[name="generator"]', attribute: 'content', pattern: /Drupal/i },
      { selector: 'link', attribute: 'href', pattern: /(\/sites\/\S+\/files|\/sites\/all\/themes|\/sites\/default\/themes)/i }
    ]
  },
  magento: {
    paths: ['/admin/', '/index.php/admin/', '/magento/'],
    headers: { 'x-magento-cache-debug': /./ },
    content: [
      { selector: 'script', attribute: 'src', pattern: /mage\/|magento/i },
      { selector: '[data-role]', attribute: 'data-role', pattern: /mage/i }
    ]
  }
};

/**
 * Detect CMS from a website
 * @param {string} url - URL to scan
 * @param {object} options - Options for detection
 * @returns {Promise<object>} - CMS detection results
 */
async function detectCMS(url, options = {}) {
  const targetUrl = url.startsWith('http') ? url : `https://${url}`;
  let cmsType = null;
  let cmsVersion = null;
  let confidence = 0;
  const evidence = [];
  
  try {
    // Get root page
    const response = await axios.get(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      timeout: options.timeout || 10000,
      maxRedirects: 2,
      validateStatus: () => true
    });
    
    const headers = response.headers;
    const body = response.data;
    
    // Load HTML content into cheerio for analysis
    const $ = cheerio.load(body);
    
    // Check for each CMS
    for (const [cms, patterns] of Object.entries(CMS_PATTERNS)) {
      let cmsScore = 0;
      
      // Check headers
      if (patterns.headers) {
        for (const [header, pattern] of Object.entries(patterns.headers)) {
          if (headers[header] && pattern.test(headers[header])) {
            cmsScore += 20;
            evidence.push(`Header ${header}: ${headers[header]}`);
          }
        }
      }
      
      // Check content patterns
      if (patterns.content) {
        for (const contentPattern of patterns.content) {
          const elements = $(contentPattern.selector);
          if (elements.length > 0) {
            let matched = false;
            elements.each((i, el) => {
              const attributes = contentPattern.attribute.split(',');
              for (const attr of attributes) {
                const value = $(el).attr(attr);
                if (value && contentPattern.pattern.test(value)) {
                  cmsScore += 15;
                  evidence.push(`Content match: ${contentPattern.selector}[${attr}="${value}"]`);
                  matched = true;
                  break;
                }
              }
              return !matched; // Stop iteration if matched
            });
          }
        }
      }

      // Try path-based detection
      if (patterns.paths) {
        const pathChecks = await Promise.all(
          patterns.paths.map(async (checkPath) => {
            try {
              const checkUrl = new URL(checkPath, targetUrl).toString();
              const res = await axios.get(checkUrl, {
                headers: {
                  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                },
                timeout: 5000,
                maxRedirects: 0,
                validateStatus: () => true
              });
              // If path exists and response is not 404
              if (res.status !== 404) {
                return { path: checkPath, status: res.status };
              }
              return null;
            } catch (error) {
              return null;
            }
          })
        );
        
        const validPaths = pathChecks.filter(p => p !== null);
        if (validPaths.length > 0) {
          cmsScore += validPaths.length * 10;
          validPaths.forEach(p => {
            evidence.push(`Path check: ${p.path} (Status: ${p.status})`);
          });
        }
      }
      
      // Update if this is the highest confidence CMS
      if (cmsScore > confidence) {
        cmsType = cms;
        confidence = cmsScore;
      }
    }
    
    // Try to determine version if CMS detected
    if (cmsType) {
      cmsVersion = await detectCMSVersion(cmsType, targetUrl, $, headers);
    }
    
  } catch (error) {
    return {
      detected: false,
      error: error.message
    };
  }
  
  return {
    detected: confidence > 20,
    cmsType: cmsType,
    version: cmsVersion,
    confidence: confidence > 100 ? 100 : confidence,
    evidence: evidence
  };
}

/**
 * Attempt to detect CMS version
 * @param {string} cmsType - Type of CMS detected
 * @param {string} url - Target URL
 * @param {object} $ - Cheerio instance with loaded page
 * @param {object} headers - Response headers
 * @returns {Promise<string|null>} - Detected version or null
 */
async function detectCMSVersion(cmsType, url, $, headers) {
  switch (cmsType) {
    case 'wordpress':
      // Check meta generator tag
      const metaVersion = $('meta[name="generator"]').attr('content');
      if (metaVersion && /WordPress\s+([\d\.]+)/i.test(metaVersion)) {
        return metaVersion.match(/WordPress\s+([\d\.]+)/i)[1];
      }
      
      // Check for version in readme.html
      try {
        const readmeUrl = new URL('/readme.html', url).toString();
        const readmeRes = await axios.get(readmeUrl, { timeout: 5000 });
        const $readme = cheerio.load(readmeRes.data);
        const readmeVersion = $readme('h1').text().match(/Version\s+([\d\.]+)/i);
        if (readmeVersion) return readmeVersion[1];
      } catch (e) { /* Ignore errors */ }
      
      break;
      
    case 'joomla':
      // Try various version detection methods for Joomla
      const jVersion = $('meta[name="generator"]').attr('content');
      if (jVersion && /Joomla!\s+([\d\.]+)/i.test(jVersion)) {
        return jVersion.match(/Joomla!\s+([\d\.]+)/i)[1];
      }
      break;
      
    case 'drupal':
      // Try to get Drupal version
      const dVersion = $('meta[name="generator"]').attr('content');
      if (dVersion && /Drupal\s+([\d\.]+)/i.test(dVersion)) {
        return dVersion.match(/Drupal\s+([\d\.]+)/i)[1];
      }
      break;
      
    case 'magento':
      // Magento version detection is complex, often requires more advanced checks
      return 'Unknown'; // Magento often hides its version
  }
  
  return null;
}

/**
 * Scan for common CMS vulnerabilities
 * @param {string} url - Target URL to scan 
 * @param {object} options - Scan options
 * @returns {Promise<object>} - Vulnerability scan results
 */
async function scanCMSVulnerabilities(url, options = {}) {
  // First detect the CMS
  const cmsInfo = await detectCMS(url, options);
  
  if (!cmsInfo.detected) {
    return {
      url,
      timestamp: new Date().toISOString(),
      cmsDetected: false,
      message: "No CMS detected"
    };
  }
  
  // Initialize result object
  const result = {
    url,
    timestamp: new Date().toISOString(),
    cmsDetected: true,
    cms: {
      name: cmsInfo.cmsType,
      version: cmsInfo.version,
      confidence: cmsInfo.confidence
    },
    vulnerabilities: []
  };
  
  // Perform CMS-specific vulnerability checks
  switch (cmsInfo.cmsType) {
    case 'wordpress':
      result.vulnerabilities = await scanWordPressVulnerabilities(url, cmsInfo.version);
      break;
    case 'joomla':
      result.vulnerabilities = await scanJoomlaVulnerabilities(url, cmsInfo.version);
      break;
    case 'drupal':
      result.vulnerabilities = await scanDrupalVulnerabilities(url, cmsInfo.version);
      break;
    case 'magento':
      result.vulnerabilities = await scanMagentoVulnerabilities(url, cmsInfo.version);
      break;
    default:
      result.vulnerabilities = [];
  }
  
  // Add overall risk assessment
  result.riskLevel = calculateRiskLevel(result.vulnerabilities);
  return result;
}

/**
 * Scan for WordPress vulnerabilities
 * @param {string} url - Target WordPress site URL
 * @param {string} version - WordPress version (if known)
 * @returns {Promise<Array>} - Found vulnerabilities
 */
async function scanWordPressVulnerabilities(url, version) {
  const vulnerabilities = [];
  const targetUrl = url.startsWith('http') ? url : `https://${url}`;
  
  try {
    // Check for user enumeration
    try {
      const authorRes = await axios.get(`${targetUrl}/?author=1`, {
        maxRedirects: 5,
        timeout: 5000,
        validateStatus: () => true
      });
      
      if (authorRes.request.res.responseUrl && 
          /\/author\/\w+/i.test(authorRes.request.res.responseUrl)) {
        vulnerabilities.push({
          name: "User Enumeration Vulnerability",
          description: "WordPress user information can be enumerated via author parameter",
          severity: "Medium",
          evidence: `?author=1 redirects to ${authorRes.request.res.responseUrl}`
        });
      }
    } catch (e) { /* Ignore errors */ }
    
    // Check for exposed version
    if (version) {
      vulnerabilities.push({
        name: "WordPress Version Exposure",
        description: `WordPress version ${version} is exposed which may help attackers identify vulnerabilities`,
        severity: "Low",
        evidence: `Detected version: ${version}`
      });
      
      // Check for outdated version (simplified)
      const isOutdated = checkOutdatedWordPressVersion(version);
      if (isOutdated) {
        vulnerabilities.push({
          name: "Outdated WordPress",
          description: `WordPress version ${version} is outdated and may contain known vulnerabilities`,
          severity: "High",
          evidence: `Current version: ${version}, Recommended: latest`
        });
      }
    }
    
    // Check for login page exposure
    try {
      const loginRes = await axios.get(`${targetUrl}/wp-login.php`, {
        timeout: 5000,
        validateStatus: () => true
      });
      
      if (loginRes.status === 200) {
        vulnerabilities.push({
          name: "Exposed Login Page",
          description: "WordPress login page is accessible, consider protecting it",
          severity: "Low",
          evidence: "wp-login.php is accessible"
        });
      }
    } catch (e) { /* Ignore errors */ }
    
  } catch (error) {
    vulnerabilities.push({
      name: "Scan Error",
      description: `Error during vulnerability scan: ${error.message}`,
      severity: "Unknown"
    });
  }
  
  return vulnerabilities;
}

// Simplified function to check if WordPress version is outdated
function checkOutdatedWordPressVersion(version) {
  if (!version) return true;
  
  // This is a simplified check - in a real implementation, 
  // you would compare against latest release data
  const versionParts = version.split('.').map(Number);
  if (versionParts[0] < 5) return true;
  if (versionParts[0] === 5 && versionParts[1] < 8) return true;
  
  return false;
}

// Placeholder functions for other CMS vulnerability scans
async function scanJoomlaVulnerabilities(url, version) {
  // Implementation similar to scanWordPressVulnerabilities
  // For now, return a placeholder result
  return [{
    name: "Scan Placeholder",
    description: "Joomla vulnerability scanning will be implemented in future versions",
    severity: "Unknown"
  }];
}

async function scanDrupalVulnerabilities(url, version) {
  // Implementation similar to scanWordPressVulnerabilities
  // For now, return a placeholder result
  return [{
    name: "Scan Placeholder",
    description: "Drupal vulnerability scanning will be implemented in future versions",
    severity: "Unknown"
  }];
}

async function scanMagentoVulnerabilities(url, version) {
  // Implementation similar to scanWordPressVulnerabilities
  // For now, return a placeholder result
  return [{
    name: "Scan Placeholder",
    description: "Magento vulnerability scanning will be implemented in future versions",
    severity: "Unknown"
  }];
}

/**
 * Calculate risk level based on vulnerabilities
 * @param {Array} vulnerabilities - List of found vulnerabilities
 * @returns {string} - Risk level (Low, Medium, High, Critical)
 */
function calculateRiskLevel(vulnerabilities) {
  if (!vulnerabilities || vulnerabilities.length === 0) return "Low";
  
  const hasCritical = vulnerabilities.some(v => v.severity === "Critical");
  const hasHigh = vulnerabilities.some(v => v.severity === "High");
  const hasMedium = vulnerabilities.some(v => v.severity === "Medium");
  
  if (hasCritical) return "Critical";
  if (hasHigh) return "High";
  if (hasMedium) return "Medium";
  return "Low";
}

module.exports = {
  detectCMS,
  scanCMSVulnerabilities
};
