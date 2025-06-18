const axios = require('axios');
const { scanClientSideVulnerabilities, interactiveScan, analyzeContentSecurity } = require('./browser');
const { extractDomainInfo } = require('./whois');
const semver = require('semver');
const path = require('path');
const fs = require('fs').promises;

// Common vulnerability databases - we would integrate with real APIs in production
// Note: This is a simplified implementation
const VULNERABILITY_DATABASES = {
  // Map common libraries to known vulnerabilities
  // Format: { libraryName: { vulnerable_versions: String, description: String, severity: String } }
  jquery: [
    { vulnerable_versions: '<3.5.0', description: 'Cross-site scripting vulnerability in jQuery.htmlPrefilter', severity: 'HIGH', cve: 'CVE-2020-11022' },
    { vulnerable_versions: '<3.4.0', description: 'jQuery before 3.4.0 is vulnerable to prototype pollution', severity: 'MEDIUM', cve: 'CVE-2019-11358' },
    { vulnerable_versions: '<3.0.0', description: 'XSS via DOM manipulation', severity: 'MEDIUM', cve: 'CVE-2015-9251' },
  ],
  bootstrap: [
    { vulnerable_versions: '<3.4.1', description: 'XSS vulnerability in Bootstrap data-template attribute', severity: 'MEDIUM', cve: 'CVE-2019-8331' },
    { vulnerable_versions: '<4.3.1', description: 'XSS vulnerability in Bootstrap tooltip component', severity: 'MEDIUM', cve: 'CVE-2018-14041' },
  ],
  react: [
    { vulnerable_versions: '<16.4.2', description: 'React DOM XSS vulnerability', severity: 'HIGH', cve: 'CVE-2018-6341' },
    { vulnerable_versions: '<16.0.1', description: 'React DOM vulnerable to XSS through SVG', severity: 'HIGH', cve: 'CVE-2017-11428' },
  ],
  angular: [
    { vulnerable_versions: '<1.8.0', description: 'Angular.js vulnerable to XSS attack', severity: 'HIGH', cve: 'CVE-2020-7676' },
    { vulnerable_versions: '<1.7.9', description: 'Sanitization bypass in Angular', severity: 'MEDIUM', cve: 'CVE-2019-10744' },
  ],
  lodash: [
    { vulnerable_versions: '<4.17.15', description: 'Prototype pollution in Lodash', severity: 'HIGH', cve: 'CVE-2019-10744' },
    { vulnerable_versions: '<4.17.12', description: 'Prototype pollution in Lodash via zipObjectDeep', severity: 'CRITICAL', cve: 'CVE-2019-10744' },
  ],
  // Add more libraries and vulnerabilities as needed
};

/**
 * Check for known vulnerabilities in detected libraries
 * @param {Array} libraries - Array of detected libraries with versions
 * @returns {Array} - List of identified vulnerabilities
 */
function checkLibraryVulnerabilities(libraries) {
  const vulnerabilities = [];
  
  libraries.forEach(lib => {
    const { name, version } = parseLibrary(lib);
    if (!name) return;
    
    // Check if library is in our database
    const knownVulns = VULNERABILITY_DATABASES[name.toLowerCase()];
    if (!knownVulns || !version) return;
    
    // Check each vulnerability against the detected version
    knownVulns.forEach(vuln => {
      if (semver.satisfies(version, vuln.vulnerable_versions)) {
        vulnerabilities.push({
          library: name,
          version: version,
          description: vuln.description,
          severity: vuln.severity,
          cve: vuln.cve || 'Unknown',
          recommendation: `Update ${name} to a version that is not ${vuln.vulnerable_versions}`
        });
      }
    });
  });
  
  return vulnerabilities;
}

/**
 * Parse library name and version from a string
 * @param {string} libraryString - String like "jQuery v3.2.1"
 * @returns {Object} - Object with name and version
 */
function parseLibrary(libraryString) {
  // Try to match common patterns like "jQuery v3.2.1", "React 16.8.0"
  const match = libraryString.match(/([a-zA-Z0-9_.-]+)(?:\.js)?\s*(?:v|version)?\s*([0-9]+(?:\.[0-9]+)+)/i);
  if (match) {
    return { name: match[1], version: match[2] };
  }
  
  // Just return the name if no version is found
  return { name: libraryString, version: null };
}

/**
 * Analyze security of a web page using Puppeteer
 * @param {string} url - URL to scan
 * @param {Object} options - Scan options
 * @returns {Promise<Object>} - Security analysis results
 */
async function scanForVulnerabilities(url, options = {}) {
  const targetUrl = url.startsWith('http') ? url : `https://${url}`;
  
  // Extract domain safely with fallback
  let domain;
  try {
    const domainInfo = extractDomainInfo(url);
    domain = domainInfo && domainInfo.domain ? domainInfo.domain : new URL(targetUrl).hostname;
  } catch (error) {
    // Fallback if domain extraction fails
    try {
      domain = new URL(targetUrl).hostname;
    } catch (urlError) {
      domain = url.replace(/[^a-zA-Z0-9.-]/g, '-');
    }
  }
  
  // Create output directory for artifacts if needed
  let outputDir = null;
  if (options.saveArtifacts) {
    outputDir = path.join(process.cwd(), 'scan-artifacts', domain);
    await fs.mkdir(outputDir, { recursive: true }).catch(() => {});
  }
  
  try {
    // Client-side vulnerability scan
    const clientSideResults = await scanClientSideVulnerabilities(targetUrl);
    
    // If credentials provided and interactive testing is enabled
    let interactiveResults = null;
    if (options.credentials && options.credentials.username && options.credentials.password) {
      interactiveResults = await interactiveScan(targetUrl, options.credentials);
    }
    
    // Content security analysis
    const contentSecurityResults = await analyzeContentSecurity(targetUrl);

    // Analyze security headers from results
    const securityHeaders = clientSideResults.securityHeaders || {};
    const headerAnalysis = analyzeSecurityHeaders(securityHeaders);
    
    // Save screenshot if artifacts are requested
    let screenshotPath = null;
    if (options.saveArtifacts && outputDir) {
      screenshotPath = path.join(outputDir, `${domain}-screenshot.png`);
      await captureScreenshot(targetUrl, screenshotPath);
    }
    
    // Identify potential vulnerabilities
    const vulnerabilities = [];

    // Check for client-side vulnerabilities
    if (clientSideResults.securityChecks.mixedContent.hasMixedContent) {
      vulnerabilities.push({
        type: 'Mixed Content',
        severity: 'HIGH',
        description: 'The page loads resources over insecure HTTP connections',
        evidence: clientSideResults.securityChecks.mixedContent.insecureElements.map(el => `${el.tag}: ${el.src}`).join(', '),
        remediation: 'Update all resource URLs to use HTTPS instead of HTTP'
      });
    }
    
    // Check for DOM XSS vulnerabilities
    const domXssChecks = clientSideResults.securityChecks.domBasedXssVectors;
    if (domXssChecks.useOfDocumentWrite || domXssChecks.useOfEval || 
        domXssChecks.useOfInnerHTML || domXssChecks.useOfSetAttribute) {
      
      let evidence = [];
      if (domXssChecks.useOfDocumentWrite) evidence.push('document.write() usage');
      if (domXssChecks.useOfEval) evidence.push('eval() usage');
      if (domXssChecks.useOfInnerHTML) evidence.push('innerHTML manipulation');
      if (domXssChecks.useOfSetAttribute) evidence.push('setAttribute with dangerous attributes');
      
      vulnerabilities.push({
        type: 'Potential DOM-based XSS',
        severity: 'HIGH',
        description: 'The page uses JavaScript methods that could lead to DOM-based XSS attacks',
        evidence: evidence.join(', '),
        remediation: 'Avoid using unsafe DOM manipulation methods. Use safer alternatives like textContent instead of innerHTML'
      });
    }
    
    // Check for potentially sensitive information in DOM
    const sensitiveInfoChecks = clientSideResults.securityChecks.sensitiveInfoInDom;
    if (sensitiveInfoChecks.possibleApiKeys || 
        sensitiveInfoChecks.possibleEmailAddresses || 
        sensitiveInfoChecks.possiblePhoneNumbers) {
      
      let evidence = [];
      if (sensitiveInfoChecks.possibleApiKeys) evidence.push('API keys or tokens');
      if (sensitiveInfoChecks.possibleEmailAddresses) evidence.push('Email addresses');
      if (sensitiveInfoChecks.possiblePhoneNumbers) evidence.push('Phone numbers');
      
      vulnerabilities.push({
        type: 'Sensitive Information Exposure',
        severity: 'MEDIUM',
        description: 'The page may expose sensitive information in the page source',
        evidence: evidence.join(', '),
        remediation: 'Avoid exposing sensitive data in client-side code'
      });
    }

    // Check forms for security issues
    if (clientSideResults.forms && clientSideResults.forms.length > 0) {
      clientSideResults.forms.forEach(form => {
        // Check for sensitive forms without HTTPS
        if (form.hasSensitiveFields && !form.isSecureSubmission) {
          vulnerabilities.push({
            type: 'Insecure Form Submission',
            severity: 'HIGH',
            description: `Form with sensitive data is submitted over HTTP (Form ID: ${form.id})`,
            evidence: `Form action: ${form.action}`,
            remediation: 'Change form submission to use HTTPS'
          });
        }
        
        // Check for forms without CSRF protection
        if (form.method === 'POST' && !form.hasCSRFToken) {
          vulnerabilities.push({
            type: 'Missing CSRF Protection',
            severity: 'MEDIUM',
            description: `Form may be missing CSRF protection (Form ID: ${form.id})`,
            evidence: `Form method: ${form.method}, No CSRF token detected`,
            remediation: 'Implement CSRF tokens for all forms that modify data'
          });
        }
      });
    }

    // Check for JWT storage issues
    if (interactiveResults && interactiveResults.securityRisks.jwtInInsecureStorage) {
      vulnerabilities.push({
        type: 'Insecure JWT Storage',
        severity: 'HIGH',
        description: 'JWT tokens are stored in localStorage which is vulnerable to XSS attacks',
        evidence: 'JWT token found in localStorage',
        remediation: 'Store authentication tokens in HttpOnly cookies instead of localStorage'
      });
    }

    // Check iframe security
    if (contentSecurityResults.iframeAnalysis.securityRisk) {
      vulnerabilities.push({
        type: 'Insecure Iframe Configuration',
        severity: 'MEDIUM',
        description: 'Iframes with both allow-scripts and allow-same-origin permissions can bypass Same Origin Policy',
        evidence: 'Iframes with both allow-scripts and allow-same-origin found',
        remediation: 'Avoid combining allow-scripts and allow-same-origin in iframe sandbox attributes'
      });
    }

    // Check for missing security headers
    headerAnalysis.missingHeaders.forEach(header => {
      vulnerabilities.push({
        type: 'Missing Security Header',
        severity: header.severity,
        description: `The security header "${header.name}" is missing`,
        evidence: 'Header not found in response',
        remediation: header.recommendation
      });
    });

    // Compile the final results
    const results = {
      url: targetUrl,
      timestamp: new Date().toISOString(),
      clientSideSecurity: {
        jsErrors: clientSideResults.jsErrors.slice(0, 10), // Limit to first 10 errors
        detectedLibraries: clientSideResults.detectedJsLibraries,
        mixedContentIssues: clientSideResults.securityChecks.mixedContent.hasMixedContent,
        formAnalysis: clientSideResults.forms
      },
      securityHeaders: headerAnalysis,
      vulnerabilities: vulnerabilities,
      contentSecurity: {
        thirdPartyDomains: contentSecurityResults.thirdPartyCount,
        iframeUsage: contentSecurityResults.iframeAnalysis
      },
      artifacts: {
        screenshotPath: screenshotPath
      }
    };

    // Add interactive results if available
    if (interactiveResults) {
      results.interactiveTesting = {
        loginSuccess: interactiveResults.loginAttempt.success,
        cookiesSet: interactiveResults.cookies.length,
        localStorageItems: Object.keys(interactiveResults.sessionAnalysis.localStorage).length,
        sessionStorageItems: Object.keys(interactiveResults.sessionAnalysis.sessionStorage).length,
        sensitiveDataInStorage: interactiveResults.securityRisks.sensitiveDataInStorage
      };
    }

    // Calculate risk score based on vulnerability count and severity
    results.riskScore = calculateRiskScore(vulnerabilities);

    return results;
  } catch (error) {
    console.error(`Error scanning for vulnerabilities: ${error.message}`);
    return {
      url: targetUrl,
      error: error.message,
      timestamp: new Date().toISOString()
    };
  }
}

/**
 * Analyze response headers for security best practices
 * @param {Object} headers - Response headers from the request
 * @returns {Object} - Analysis of the security headers
 */
function analyzeSecurityHeaders(headers) {
  // Convert header names to lowercase for consistent comparison
  const normalizedHeaders = {};
  Object.keys(headers).forEach(key => {
    normalizedHeaders[key.toLowerCase()] = headers[key];
  });
  
  // Define important security headers and their impact
  const securityHeaderChecks = [
    {
      name: 'Strict-Transport-Security',
      headerName: 'strict-transport-security',
      severity: 'HIGH',
      recommendation: 'Add Strict-Transport-Security header with "max-age=31536000" for all domain scopes'
    },
    {
      name: 'Content-Security-Policy',
      headerName: 'content-security-policy',
      severity: 'HIGH',
      recommendation: 'Implement a Content Security Policy to prevent XSS and data injection attacks'
    },
    {
      name: 'X-Content-Type-Options',
      headerName: 'x-content-type-options',
      severity: 'MEDIUM',
      recommendation: 'Add X-Content-Type-Options header with value "nosniff"'
    },
    {
      name: 'X-Frame-Options',
      headerName: 'x-frame-options',
      severity: 'MEDIUM',
      recommendation: 'Add X-Frame-Options header with value "SAMEORIGIN" to prevent clickjacking'
    },
    {
      name: 'X-XSS-Protection',
      headerName: 'x-xss-protection',
      severity: 'MEDIUM',
      recommendation: 'Add X-XSS-Protection header with value "1; mode=block"'
    },
    {
      name: 'Referrer-Policy',
      headerName: 'referrer-policy',
      severity: 'LOW',
      recommendation: 'Add Referrer-Policy header to control information passed in the Referer header'
    },
    {
      name: 'Permissions-Policy',
      headerName: 'permissions-policy',
      severity: 'LOW',
      recommendation: 'Add Permissions-Policy header to control browser features'
    }
  ];
  
  // Check which security headers are present and which are missing
  const presentHeaders = [];
  const missingHeaders = [];
  
  securityHeaderChecks.forEach(check => {
    const headerValue = normalizedHeaders[check.headerName];
    
    if (headerValue) {
      presentHeaders.push({
        name: check.name,
        value: headerValue
      });
    } else {
      missingHeaders.push({
        name: check.name,
        severity: check.severity,
        recommendation: check.recommendation
      });
    }
  });
  
  return {
    presentHeaders,
    missingHeaders,
    headerCount: Object.keys(headers).length,
    securityHeaderCount: presentHeaders.length,
    securityScore: calculateSecurityHeaderScore(presentHeaders, securityHeaderChecks.length)
  };
}

/**
 * Calculate security score based on present headers
 * @param {Array} presentHeaders - Array of present security headers
 * @param {number} totalHeaders - Total number of security headers checked
 * @returns {number} - Score from 0-100
 */
function calculateSecurityHeaderScore(presentHeaders, totalHeaders) {
  if (totalHeaders === 0) return 0;
  return Math.round((presentHeaders.length / totalHeaders) * 100);
}

/**
 * Calculate overall risk score based on vulnerabilities
 * @param {Array} vulnerabilities - Array of identified vulnerabilities
 * @returns {Object} - Risk score details
 */
function calculateRiskScore(vulnerabilities) {
  // Count vulnerabilities by severity
  const severityCounts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };
  
  vulnerabilities.forEach(vuln => {
    if (severityCounts[vuln.severity]) {
      severityCounts[vuln.severity]++;
    } else {
      severityCounts[vuln.severity] = 1;
    }
  });
  
  // Calculate weighted score
  // CRITICAL issues are worth 10 points, HIGH 5 points, MEDIUM 2 points, LOW 1 point
  const weights = {
    CRITICAL: 10,
    HIGH: 5,
    MEDIUM: 2,
    LOW: 1
  };
  
  let weightedScore = 0;
  for (const severity in severityCounts) {
    weightedScore += severityCounts[severity] * weights[severity];
  }
  
  // Calculate score out of 100
  // 0 is best (no vulnerabilities), 100 is worst
  const score = Math.min(100, weightedScore * 2);
  
  // Determine risk level based on score
  let riskLevel;
  if (score <= 10) {
    riskLevel = 'LOW';
  } else if (score <= 40) {
    riskLevel = 'MEDIUM';
  } else if (score <= 70) {
    riskLevel = 'HIGH';
  } else {
    riskLevel = 'CRITICAL';
  }
  
  return {
    score,
    riskLevel,
    vulnerabilitiesBySeverity: severityCounts,
    totalVulnerabilities: vulnerabilities.length
  };
}

module.exports = {
  scanForVulnerabilities
};
