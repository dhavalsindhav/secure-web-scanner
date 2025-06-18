const { isBrowser } = require('./browser-compatibility');

const { getSSLInfo, analyzeSSL } = require('./ssl');
const { checkHeaders, analyzeHeaders } = require('./headers');
const { detectTechStack, analyzeTechStackSecurity } = require('./techStack');
const { getWhoisInfo, extractDomainInfo } = require('./whois');
const { checkDns, analyzeDnsSecurity } = require('./dns');
const { scanPorts, analyzePortSecurity, PORT_GROUPS } = require('./ports');
const { checkCookies, analyzeCookieSecurity } = require('./cookies');
const { checkCSP, analyzeCSP } = require('./csp');
const { scanForVulnerabilities } = require('./vulnscan');
const { captureScreenshot, extractLinks, analyzeContentSecurity } = require('./browser');
const { findLiveSubdomains, formatSubdomainResults } = require('./subdomains');
// Import existing modules
const { enhancedPortScan, fingerprintService } = require('./network');
const { detectCMS, scanCMSVulnerabilities } = require('./cms');
const { performRecon, checkCertificateTransparency } = require('./recon');
const { scanWeb } = require('./web');

// Import new enhanced modules
const { scanApi, analyzeApiSpec, activeApiTesting } = require('./apisec');
const { detectVulnerabilities, analyzeSourceCodeWithAI } = require('./ai');
const { scanCloud, analyzeCloudConfig } = require('./cloudsec');
const { scanDependencies } = require('./supplychainsec');
const { generateReport, serveDashboard } = require('./reporting');

/**
 * Helper function to extract root domain from subdomain
 * @param {string} domain - Domain or subdomain
 * @returns {string} - Root domain
 */
function getRootDomain(domain) {
  // Simple implementation - split by dots and take the last two parts
  const parts = domain.split('.');
  if (parts.length <= 2) return domain;
  return parts.slice(-2).join('.');
}

/**
 * Main scanner function that combines all modules
 * @param {string} target - URL or domain to scan
 * @param {object} options - Scan options
 * @returns {Promise<object>} - Comprehensive scan results
 */
async function scan(target, options = {}) {
  // Default options
  const defaultOptions = {
    scanId: null,         // Unique scan identifier
    checkSSL: true,
    checkHeaders: true,
    detectTech: true,
    getWhois: false,      // Optional as it might be rate-limited
    checkDns: false,      // DNS checks are optional
    scanPorts: false,     // Port scanning is optional
    checkCookies: true,   // Cookie security checks
    checkCSP: true,       // CSP header analysis
    advancedTechDetection: false, // In-depth technology detection
    focusOnVulnerabilities: false, // Focus on finding vulnerabilities
    portScanLevel: 'minimal', // Default to minimal port scan
    fingerprint: false,   // Whether to fingerprint services on open ports
    ports: null,          // Custom ports to scan (null = use selected portScanLevel)
    timeout: 30000,
    // Puppeteer-based advanced scanning options
    usePuppeteer: false,  // Whether to use Puppeteer for advanced scanning
    puppeteerOptions: {
      takeScreenshot: false,  // Take screenshot of the target
      screenshotPath: null,   // Path to save screenshot (null = auto-generate)
      scanClientSideVulns: false, // Scan for client-side vulnerabilities
      extractLinks: false,     // Extract all links from the page
      interactiveScan: false,  // Perform interactive scanning (e.g., form submission)
      contentSecurityAnalysis: false, // Analyze content security (iframes, 3rd-party resources)
      credentials: null,       // Optional credentials for login testing {username, password}
      saveArtifacts: false     // Save scan artifacts (screenshots, DOM dumps, etc.)
    },
    // New advanced module options
    useAI: false,         // Use AI to analyze vulnerabilities
    apiScan: false,       // Scan for API endpoints and vulnerabilities
    authScan: false,      // Analyze authentication mechanisms
    cloudScan: false,     // Scan cloud infrastructure/configs
    depsScan: false,      // Scan project dependencies
    interactiveDashboard: false, // Start interactive dashboard after scan
    dashboardPort: 3000,  // Port for interactive dashboard
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
    rootDomain: getRootDomain(domainOnly),
    timestamp: new Date().toISOString(),
    scanOptions,
    ssl: null,
    headers: null,
    techStack: null,
    whois: null,
    dns: null,
    ports: null,
    cookies: null,
    csp: null,
    puppeteer: null,  // Results from Puppeteer-based scanning
    // New advanced module results
    aiInsights: null,
    apiSecurity: null,
    authSecurity: null,
    cloudSecurity: null,
    dependencySecurity: null
  };

  // Run selected scans in parallel
  const promises = [];
  
  if (scanOptions.checkSSL) {
    promises.push(
      getSSLInfo(domainOnly).then(sslInfo => {
        results.ssl = {
          raw: sslInfo,
          analysis: analyzeSSL(sslInfo)
        };
      })
    );
  }
  
  if (scanOptions.checkHeaders) {
    promises.push(
      checkHeaders(fullUrl).then(headerData => {
        results.headers = {
          raw: headerData,
          analysis: analyzeHeaders(headerData)
        };
      })
    );
  }
    if (scanOptions.detectTech) {
    promises.push(
      detectTechStack(fullUrl, {
      detectionLevel: scanOptions.advancedTechDetection ? 'deep' : 'standard',
      timeout: scanOptions.timeout,
      checkVulnerabilities: true,
      focusOnVulnerabilities: scanOptions.focusOnVulnerabilities || false
      }).then(techData => {
        results.techStack = {
          ...techData,
          analysis: analyzeTechStackSecurity(techData)
        };
      })
    );
  }
  
  if (scanOptions.getWhois) {
    promises.push(
      getWhoisInfo(domainOnly).then(whoisData => {
        results.whois = {
          raw: whoisData,
          simplified: extractDomainInfo(whoisData)
        };
      })
    );
  }
  
  // New advanced scanners
  if (scanOptions.checkDns) {
    promises.push(
      checkDns(domainOnly).then(dnsData => {
        results.dns = {
          raw: dnsData,
          analysis: analyzeDnsSecurity(dnsData)
        };
      })
    );
  }
  
  if (scanOptions.scanPorts) {
    // Determine ports to scan
    let portsToScan = scanOptions.ports;
    if (!portsToScan && scanOptions.portScanLevel) {
      portsToScan = scanOptions.portScanLevel;
    }
    
    promises.push(
      scanPorts(domainOnly, portsToScan, scanOptions.timeout, scanOptions.fingerprint).then(portData => {
        results.ports = {
          raw: portData,
          analysis: analyzePortSecurity(portData)
        };
      })
    );
  }
  
  if (scanOptions.checkCookies) {
    promises.push(
      checkCookies(fullUrl).then(cookieData => {
        results.cookies = {
          raw: cookieData,
          analysis: analyzeCookieSecurity(cookieData)
        };
      })
    );
  }
  
  if (scanOptions.checkCSP) {
    promises.push(
      checkCSP(fullUrl).then(cspData => {
        results.csp = {
          raw: cspData,
          analysis: analyzeCSP(cspData)
        };
      })
    );
  }
  // Puppeteer-based advanced scanning
  
  // Add Puppeteer-based scanning if enabled
  if (scanOptions.usePuppeteer) {
    const puppeteerOptions = scanOptions.puppeteerOptions || {};
    
    // Run vulnerability scanning with Puppeteer
    promises.push(
      scanForVulnerabilities(fullUrl, puppeteerOptions).then(vulnResults => {
        results.puppeteer = {
          vulnerabilities: vulnResults
        };
      })
    );
    
    // Capture screenshot if requested
    if (puppeteerOptions.takeScreenshot) {
      const screenshotPath = puppeteerOptions.screenshotPath || 
                            `./screenshots/${domainOnly.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.png`;
      
      promises.push(
        captureScreenshot(fullUrl, screenshotPath).then(path => {
          if (!results.puppeteer) results.puppeteer = {};
          results.puppeteer.screenshot = { path };
        })
      );
    }
    
    // Extract all links from the page
    if (puppeteerOptions.extractLinks) {
      promises.push(
        extractLinks(fullUrl, { sameDomain: true }).then(links => {
          if (!results.puppeteer) results.puppeteer = {};
          results.puppeteer.links = links;
        })
      );
    }
    
    // Analyze content security
    if (puppeteerOptions.contentSecurityAnalysis) {
      promises.push(
        analyzeContentSecurity(fullUrl).then(securityResults => {
          if (!results.puppeteer) results.puppeteer = {};
          results.puppeteer.contentSecurity = securityResults;
        })
      );
    }
  }
  
  // Wait for all scans to complete
  try {
    await Promise.all(promises);
  } catch (error) {
    // If any scan fails, continue with partial results
    console.error('Error in one of the scan modules:', error.message);
  }
  
  // Add overall security assessment
  results.securityAssessment = getOverallAssessment(results);
  
  return results;
}

/**
 * Generate an overall security assessment based on all scan results
 * @param {object} results - Scan results
 * @returns {object} - Overall security assessment
 */
function getOverallAssessment(results) {
  const assessment = {
    score: 0,
    maxScore: 0,
    percentage: 0,
    issues: [],
    warnings: [],
    recommendations: [],
    categories: {}
  };
  
  // Define category weights for the overall score
  const categoryWeights = {
    ssl: 15,        // SSL is critical
    headers: 15,    // Security headers are important
    csp: 20,        // CSP is very important for XSS prevention
    cookies: 15,    // Cookie security is important
    dns: 10,        // DNS security
    ports: 15,      // Open ports security
    techStack: 20   // Technology stack vulnerabilities
  };
  
  // Process SSL results
  if (results.ssl) {
    const weight = categoryWeights.ssl;
    assessment.maxScore += weight;
    let categoryScore = 0;
    
    if (results.ssl.raw.valid) {
      categoryScore = 0.7 * weight; // 70% for being valid
      
      // Additional points for long expiration
      if (results.ssl.raw.daysRemaining > 180) {
        categoryScore += 0.3 * weight; // Full 100% if long expiration
      } else if (results.ssl.raw.daysRemaining > 90) {
        categoryScore += 0.2 * weight; // 90% if medium expiration
      } else if (results.ssl.raw.daysRemaining > 30) {
        categoryScore += 0.1 * weight; // 80% if short expiration
      }
    }
    
    assessment.score += categoryScore;
    assessment.categories.ssl = {
      score: categoryScore,
      maxScore: weight,
      percentage: Math.round((categoryScore / weight) * 100)
    };
    
    // Add SSL issues and warnings
    if (results.ssl.analysis.issues && results.ssl.analysis.issues.length) {
      assessment.issues.push(...results.ssl.analysis.issues);
    }
    
    if (results.ssl.analysis.warnings && results.ssl.analysis.warnings.length) {
      assessment.warnings.push(...results.ssl.analysis.warnings);
    }
  }
  
  // Process headers results
  if (results.headers && results.headers.analysis) {
    const weight = categoryWeights.headers;
    assessment.maxScore += weight;
    
    const headerAnalysis = results.headers.analysis;
    const headerDetails = headerAnalysis.headerDetails || {};
    const headerCount = Object.keys(headerDetails).length;
    
    // Base score for having security headers
    const securityHeadersCount = Object.values(headerDetails)
      .filter(h => h.present).length;
    
    // Calculate score as percentage of present headers
    const categoryScore = headerCount > 0 
      ? (securityHeadersCount / headerCount) * weight
      : 0;
    
    assessment.score += categoryScore;
    assessment.categories.headers = {
      score: categoryScore,
      maxScore: weight,
      percentage: Math.round((categoryScore / weight) * 100)
    };
    
    // Add header issues and warnings
    if (headerAnalysis.issues && headerAnalysis.issues.length) {
      assessment.issues.push(...headerAnalysis.issues);
    }
    
    if (headerAnalysis.warnings && headerAnalysis.warnings.length) {
      assessment.warnings.push(...headerAnalysis.warnings);
    }
  }
  
  // Process Content Security Policy results
  if (results.csp && results.csp.analysis) {
    const weight = categoryWeights.csp;
    assessment.maxScore += weight;
    
    const cspAnalysis = results.csp.analysis;
    const categoryScore = (cspAnalysis.score / 100) * weight;
    
    assessment.score += categoryScore;
    assessment.categories.csp = {
      score: categoryScore,
      maxScore: weight,
      percentage: cspAnalysis.percentage
    };
    
    // Add CSP issues and warnings
    if (cspAnalysis.issues && cspAnalysis.issues.length) {
      assessment.issues.push(...cspAnalysis.issues);
    }
    
    if (cspAnalysis.warnings && cspAnalysis.warnings.length) {
      assessment.warnings.push(...cspAnalysis.warnings);
    }
    
    if (cspAnalysis.recommendations && cspAnalysis.recommendations.length) {
      assessment.recommendations.push(...cspAnalysis.recommendations);
    }
  }
  
  // Process Cookie Security results
  if (results.cookies && results.cookies.analysis) {
    const weight = categoryWeights.cookies;
    assessment.maxScore += weight;
    
    const cookieAnalysis = results.cookies.analysis;
    const categoryScore = (cookieAnalysis.score / 100) * weight;
    
    assessment.score += categoryScore;
    assessment.categories.cookies = {
      score: categoryScore,
      maxScore: weight,
      percentage: cookieAnalysis.percentage
    };
    
    // Add cookie issues and warnings
    if (cookieAnalysis.issues && cookieAnalysis.issues.length) {
      assessment.issues.push(...cookieAnalysis.issues);
    }
    
    if (cookieAnalysis.warnings && cookieAnalysis.warnings.length) {
      assessment.warnings.push(...cookieAnalysis.warnings);
    }
    
    if (cookieAnalysis.recommendations && cookieAnalysis.recommendations.length) {
      assessment.recommendations.push(...cookieAnalysis.recommendations);
    }
  }
  
  // Process DNS Security results
  if (results.dns && results.dns.analysis) {
    const weight = categoryWeights.dns;
    assessment.maxScore += weight;
    
    const dnsAnalysis = results.dns.analysis;
    const categoryScore = (dnsAnalysis.score / 100) * weight;
    
    assessment.score += categoryScore;
    assessment.categories.dns = {
      score: categoryScore,
      maxScore: weight,
      percentage: dnsAnalysis.percentage
    };
    
    // Add DNS issues and warnings
    if (dnsAnalysis.issues && dnsAnalysis.issues.length) {
      assessment.issues.push(...dnsAnalysis.issues);
    }
    
    if (dnsAnalysis.warnings && dnsAnalysis.warnings.length) {
      assessment.warnings.push(...dnsAnalysis.warnings);
    }
    
    if (dnsAnalysis.recommendations && dnsAnalysis.recommendations.length) {
      assessment.recommendations.push(...dnsAnalysis.recommendations);
    }
  }
    // Process Port Scanning results
  if (results.ports && results.ports.analysis) {
    const weight = categoryWeights.ports;
    assessment.maxScore += weight;
    
    const portAnalysis = results.ports.analysis;
    // Make sure we have a valid score and percentage
    const score = portAnalysis.score || 0;
    const percentage = portAnalysis.percentage || 0;
    const categoryScore = (score / 100) * weight;
    
    assessment.score += categoryScore;
    assessment.categories.ports = {
      score: categoryScore,
      maxScore: weight,
      percentage: percentage
    };
    
    // Add port issues and warnings
    if (portAnalysis.issues && portAnalysis.issues.length) {
      assessment.issues.push(...portAnalysis.issues);
    }
    
    if (portAnalysis.warnings && portAnalysis.warnings.length) {
      assessment.warnings.push(...portAnalysis.warnings);
    }
    
    if (portAnalysis.recommendations && portAnalysis.recommendations.length) {
      assessment.recommendations.push(...portAnalysis.recommendations);
    }
  }
    // Process tech stack for outdated/vulnerable technologies
  if (results.techStack && !results.techStack.error) {
    const weight = categoryWeights.techStack;
    assessment.maxScore += weight;
    
    if (results.techStack.analysis) {
      const techAnalysis = results.techStack.analysis;
      const categoryScore = (techAnalysis.score / 100) * weight;
      
      assessment.score += categoryScore;
      assessment.categories.techStack = {
        score: categoryScore,
        maxScore: weight,
        percentage: techAnalysis.percentage
      };
      
      // Add tech stack issues and warnings
      if (techAnalysis.issues && techAnalysis.issues.length) {
        assessment.issues.push(...techAnalysis.issues);
      }
      
      if (techAnalysis.warnings && techAnalysis.warnings.length) {
        assessment.warnings.push(...techAnalysis.warnings);
      }
      
      if (techAnalysis.recommendations && techAnalysis.recommendations.length) {
        assessment.recommendations.push(...techAnalysis.recommendations);
      }
    } else {
      // Fallback if no detailed analysis available
      assessment.score += weight;      assessment.categories.techStack = {
        score: weight,
        maxScore: weight,
        percentage: 100
      }
    };
  }
  
  // Subdomain analysis removed
  
  // Calculate percentage
  if (assessment.maxScore > 0) {
    assessment.percentage = Math.round((assessment.score / assessment.maxScore) * 100);
  }
    // Deduplicate and organize recommendations based on priority
  if (assessment.issues.length > 0 || assessment.warnings.length > 0) {
    // Start with existing specific recommendations
    const recommendations = [...assessment.recommendations];
      // Helper function to detect similar recommendations
    const isDuplicate = (newRec, existingRecs) => {
      return existingRecs.some(existingRec => {
        // Remove prefixes for comparison
        const cleanNew = newRec.replace(/^(Fix|Consider): /i, '').toLowerCase();
        const cleanExisting = existingRec.replace(/^(Fix|Consider): /i, '').toLowerCase();
        
        // Check for substantial overlap
        if (cleanNew.includes(cleanExisting) || cleanExisting.includes(cleanNew)) {
          return true;
        }
        
        // Specific checks for common issues
        if (
          (cleanNew.includes('csp') && cleanExisting.includes('content security policy')) ||
          (cleanNew.includes('content security policy') && cleanExisting.includes('csp'))
        ) {
          return true;
        }
        
        // Check for high similarity in the beginning of the string
        if (cleanNew.length > 10 && cleanExisting.length > 10) {
          const newWords = cleanNew.split(' ');
          const existingWords = cleanExisting.split(' ');
          
          // Count matching words
          let matchCount = 0;
          for (let i = 0; i < Math.min(3, newWords.length); i++) {
            if (existingWords.includes(newWords[i])) {
              matchCount++;
            }
          }
          
          // If more than half of the first few words match
          if (matchCount >= 2) {
            return true;
          }
        }
        
        return false;
      });
    };
    
    // Add issues as "Fix:" recommendations if not duplicates
    for (const issue of assessment.issues) {
      const issueRec = `Fix: ${issue}`;
      if (!isDuplicate(issueRec, recommendations)) {
        recommendations.push(issueRec);
      }
    }
    
    // Add warnings as "Consider:" recommendations if not duplicates
    for (const warning of assessment.warnings) {
      const warningRec = `Consider: ${warning}`;
      if (!isDuplicate(warningRec, recommendations)) {
        recommendations.push(warningRec);
      }
    }
    
    assessment.recommendations = recommendations;
    
    // Limit to top 15 most important recommendations if there are too many
    if (assessment.recommendations.length > 15) {
      // Prioritize "Fix:" recommendations over "Consider:" ones
      const fixes = assessment.recommendations.filter(r => r.startsWith('Fix:'));
      const considerations = assessment.recommendations.filter(r => r.startsWith('Consider:'));
      const others = assessment.recommendations.filter(r => !r.startsWith('Fix:') && !r.startsWith('Consider:'));
      
      const uniqueRecommendationsCount = assessment.recommendations.length;
      
      assessment.recommendations = [
        ...fixes,
        ...considerations,
        ...others
      ].slice(0, 15);
      
      assessment.recommendations.push(`And ${uniqueRecommendationsCount - 15} more recommendations...`);
    }
  } else if (assessment.recommendations.length === 0) {
    assessment.recommendations.push('Security configuration looks good. Maintain current practices.');
  }
  
  // Determine overall status
  if (assessment.issues.length > 0) {
    assessment.status = 'issues';
    assessment.summary = `${assessment.issues.length} security issues identified. Score: ${assessment.percentage}%`;
  } else if (assessment.warnings.length > 0) {
    assessment.status = 'warnings';
    assessment.summary = `${assessment.warnings.length} security warnings identified. Score: ${assessment.percentage}%`;
  } else {
    assessment.status = 'secure';
    assessment.summary = `No security issues identified. Score: ${assessment.percentage}%`;
  }
  
  return assessment;
}

module.exports = {
  scan,
  getSSLInfo,
  analyzeSSL,
  checkHeaders,
  analyzeHeaders,
  detectTechStack,
  analyzeTechStackSecurity,
  getWhoisInfo,
  checkDns,
  analyzeDnsSecurity,
  scanPorts,
  // Export new advanced functions
  scanApi,
  analyzeApiSpec,
  activeApiTesting,
  detectVulnerabilities,
  analyzeSourceCodeWithAI,
  scanCloud,
  analyzeCloudConfig,
  scanDependencies,
  generateReport,
  serveDashboard,
  analyzeAuthForm,
  analyzePortSecurity,
  checkCookies,
  analyzeCookieSecurity,
  checkCSP,
  analyzeCSP,
  scanForVulnerabilities,
  captureScreenshot,
  extractLinks,
  // Network module exports
  enhancedPortScan,
  fingerprintService,
  // CMS module exports
  detectCMS,
  scanCMSVulnerabilities,
  // Recon module exports
  performRecon,
  checkCertificateTransparency,
  // Web module exports
  scanWeb,
  analyzeContentSecurity,
  findLiveSubdomains,
  formatSubdomainResults,
  
  // New enhanced module exports
  // API Security module
  scanApi,
  analyzeApiSpec,
  activeApiTesting,
  
  // AI-powered vulnerability detection
  detectVulnerabilities,
  analyzeSourceCodeWithAI,
  
  // Cloud security module
  scanCloud,
  analyzeCloudConfig,
  
  // Supply chain security
  scanDependencies,
  
  // Enhanced reporting
  generateReport,
  serveDashboard,
  detectCMS,
  scanCMSVulnerabilities,
  performRecon,
  checkCertificateTransparency,
  scanWeb
};
