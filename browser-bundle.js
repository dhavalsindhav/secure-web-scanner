/**
 * Browser-compatible entry point for secure-web-scanner
 * This provides a smaller subset of functionality for browser environments
 */

const { isBrowser } = require('./lib/browser-compatibility');

// Only include browser-compatible modules
const { checkHeaders, analyzeHeaders } = require('./lib/headers');
const { detectTechStack } = require('./lib/techStack');
const { checkCookies } = require('./lib/cookies');
const { checkCSP, analyzeCSP } = require('./lib/csp');
const { scanWeb } = require('./lib/web');

/**
 * Browser-compatible scanner function
 * @param {string} target - URL to scan
 * @param {object} options - Scan options
 * @returns {Promise<object>} - Scan results
 */
async function browserScan(target, options = {}) {
  if (!isBrowser) {
    console.warn('[secure-web-scanner] Using browser version in Node.js environment. For full functionality, use the standard version.');
  }

  // Default options
  const defaultOptions = {
    scanId: null,         // Unique scan identifier
    checkHeaders: true,   // Check HTTP headers
    detectTech: true,     // Detect technologies
    checkCookies: true,   // Cookie security checks
    checkCSP: true,       // CSP header analysis
    reportFormats: ['json'] // Output report formats
  };

  const scanOptions = { ...defaultOptions, ...options };
  
  // Clean target (remove protocol for domain-only operations)
  const domainOnly = target.replace(/^https?:\/\//i, '').split('/')[0];
  const fullUrl = target.startsWith('http') ? target : `https://${target}`;
  
  // Initialize results object
  const results = {
    scanId: scanOptions.scanId || `scan-${Date.now()}`,
    target,
    domain: domainOnly,
    timestamp: new Date().toISOString(),
    scanOptions: { ...scanOptions, browserBundle: true },
    headers: null,
    techStack: null,
    cookies: null,
    csp: null,
    errors: [],
  };

  try {
    // Run the browser-compatible scans
    if (scanOptions.checkHeaders) {
      results.headers = await checkHeaders(fullUrl);
      if (results.headers && !results.headers.error) {
        results.headerAnalysis = analyzeHeaders(results.headers);
      }
    }

    if (scanOptions.detectTech) {
      results.techStack = await detectTechStack(fullUrl);
    }

    if (scanOptions.checkCookies) {
      results.cookies = await checkCookies(fullUrl);
    }

    if (scanOptions.checkCSP) {
      results.csp = await checkCSP(fullUrl);
      if (results.csp && !results.csp.error) {
        results.cspAnalysis = analyzeCSP(results.csp);
      }
    }

    return results;
  } catch (error) {
    results.errors.push({
      phase: 'scan',
      message: error.message,
      stack: error.stack
    });
    return results;
  }
}

// Export browser-compatible functions
module.exports = {
  browserScan,
  checkHeaders,
  analyzeHeaders,
  detectTechStack,
  checkCookies,
  checkCSP,
  analyzeCSP,
  scanWeb,
  // Flag that indicates this is the browser bundle
  isBrowserBundle: true
};
