/**
 * Web scanning module
 * Integrates various web security scanning functions:
 * - SSL/TLS checks
 * - HTTP headers analysis  
 * - CSP analysis
 * - Cookie security
 * - Web application scanning
 */

const { getSSLInfo, analyzeSSL } = require('./ssl');
const { checkHeaders, analyzeHeaders } = require('./headers');
const { checkCSP, analyzeCSP } = require('./csp');
const { checkCookies, analyzeCookieSecurity } = require('./cookies');
const { captureScreenshot, extractLinks, analyzeContentSecurity } = require('./browser');
const axios = require('axios');
const cheerio = require('cheerio');

/**
 * Perform comprehensive web scan of a target
 * @param {string} target - Target URL to scan
 * @param {object} options - Scan options
 * @returns {Promise<object>} - Web scan results
 */
async function scanWeb(target, options = {}) {
  // Default options
  const defaultOptions = {
    ssl: true,               // SSL/TLS scanning
    headers: true,           // HTTP header analysis
    csp: true,               // Content Security Policy analysis
    cookies: true,           // Cookie security checks
    formSecurity: false,     // Check form security (CSRF, etc.)
    linkAnalysis: false,     // Analyze links (internal/external)
    contentSecurity: false,  // Content security (iframes, etc.)
    screenshot: false,       // Take screenshot
    screenshotPath: null,    // Path to save screenshot
    xssDetection: false,     // Basic XSS detection
    usePuppeteer: false      // Whether to use Puppeteer for advanced scanning
  };

  const scanOptions = { ...defaultOptions, ...options };
  
  // Normalize target URL
  const targetUrl = target.startsWith('http') ? target : `https://${target}`;
  const domain = new URL(targetUrl).hostname;
  
  // Initialize result object
  const results = {
    target: targetUrl,
    domain,
    timestamp: new Date().toISOString(),
    ssl: null,
    headers: null,
    csp: null,
    cookies: null,
    forms: null,
    links: null,
    content: null,
    screenshot: null,
    xss: null
  };
  
  // Create an array of promises for parallel execution
  const promises = [];
  
  // SSL/TLS scanning
  if (scanOptions.ssl) {
    promises.push(
      getSSLInfo(domain).then(sslInfo => {
        results.ssl = {
          raw: sslInfo,
          analysis: analyzeSSL(sslInfo)
        };
      }).catch(err => {
        results.ssl = { error: err.message };
      })
    );
  }
  
  // Get initial response for further analysis
  let response;
  try {
    response = await axios.get(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      timeout: 10000,
      maxRedirects: 3,
      validateStatus: () => true // Accept any status code
    });
  } catch (error) {
    // Handle request error
    const errorResults = {
      target: targetUrl,
      domain,
      timestamp: new Date().toISOString(),
      error: error.message,
      statusCode: error.response?.status || null
    };
    
    // We can still try SSL checks even if the web request failed
    if (scanOptions.ssl && results.ssl) {
      errorResults.ssl = results.ssl;
    }
    
    return errorResults;
  }
  
  // HTTP headers analysis
  if (scanOptions.headers) {
    const headerResults = checkHeaders(response.headers);
    results.headers = {
      raw: response.headers,
      analysis: analyzeHeaders(headerResults)
    };
  }
  
  // Content Security Policy analysis
  if (scanOptions.csp) {
    const cspHeader = response.headers['content-security-policy'] || 
                     response.headers['content-security-policy-report-only'];
    
    if (cspHeader) {
      const cspResults = checkCSP(cspHeader);
      results.csp = {
        raw: cspHeader,
        analysis: analyzeCSP(cspResults)
      };
    } else {
      results.csp = {
        raw: null,
        analysis: {
          implemented: false,
          score: 0,
          recommendations: ['Implement Content Security Policy to prevent XSS and other code injection attacks']
        }
      };
    }
  }
  
  // Cookie security analysis
  if (scanOptions.cookies) {
    const cookies = response.headers['set-cookie'] || [];
    const cookieResults = checkCookies(cookies);
    results.cookies = {
      raw: cookies,
      analysis: analyzeCookieSecurity(cookieResults)
    };
  }
  
  // Load HTML content for analysis if needed
  const $ = response.data ? cheerio.load(response.data) : null;
  
  // Form security analysis
  if (scanOptions.formSecurity && $) {
    results.forms = analyzeFormSecurity($);
  }
  
  // Link analysis
  if (scanOptions.linkAnalysis && $) {
    results.links = analyzeLinks($, targetUrl);
  }
  
  // Content security analysis
  if (scanOptions.contentSecurity) {
    if (scanOptions.usePuppeteer) {
      // Use Puppeteer for advanced content security analysis
      promises.push(
        analyzeContentSecurity(targetUrl).then(contentAnalysis => {
          results.content = contentAnalysis;
        }).catch(err => {
          results.content = { error: err.message };
        })
      );
    } else if ($) {
      // Use Cheerio for basic content security analysis
      results.content = analyzeContentSecurityBasic($);
    }
  }
  
  // Take screenshot
  if (scanOptions.screenshot && scanOptions.usePuppeteer) {
    promises.push(
      captureScreenshot(targetUrl, scanOptions.screenshotPath).then(screenshotPath => {
        results.screenshot = { path: screenshotPath };
      }).catch(err => {
        results.screenshot = { error: err.message };
      })
    );
  }
  
  // Basic XSS detection
  if (scanOptions.xssDetection && $) {
    results.xss = detectXssVulnerabilities($, targetUrl);
  }
  
  // Wait for all async operations to complete
  await Promise.allSettled(promises);
  
  // Calculate overall security score
  results.securityScore = calculateWebSecurityScore(results);
  
  return results;
}

/**
 * Analyze form security using Cheerio
 * @param {object} $ - Cheerio instance with loaded HTML
 * @returns {object} - Form security analysis
 */
function analyzeFormSecurity($) {
  const forms = $('form');
  const formResults = [];
  
  forms.each((i, form) => {
    const $form = $(form);
    const action = $form.attr('action') || '';
    const method = ($form.attr('method') || 'get').toLowerCase();
    const hasCSRF = !!$form.find('input[name*="csrf" i], input[name*="token" i], input[name*="_token" i]').length;
    const passwordField = $form.find('input[type="password"]').length > 0;
    const isLoginForm = passwordField && $form.find('input[type="text"], input[type="email"]').length > 0;
    
    const formResult = {
      id: $form.attr('id') || `form-${i}`,
      action,
      method,
      hasCSRF,
      isSecureAction: action.startsWith('https://'),
      isPostMethod: method === 'post',
      isLoginForm,
      securityIssues: []
    };
    
    // Check for security issues
    if (isLoginForm && method !== 'post') {
      formResult.securityIssues.push('Login form should use POST method');
    }
    
    if (isLoginForm && !action.startsWith('https://')) {
      formResult.securityIssues.push('Login form action should use HTTPS');
    }
    
    if (method === 'post' && !hasCSRF) {
      formResult.securityIssues.push('POST form missing CSRF token');
    }
    
    if (isLoginForm && !$form.find('input[autocomplete="off"]').length) {
      formResult.securityIssues.push('Consider using autocomplete="off" for sensitive forms');
    }
    
    formResults.push(formResult);
  });
  
  return {
    count: formResults.length,
    forms: formResults,
    hasCsrfProtection: formResults.some(form => form.hasCSRF),
    secureFormsCount: formResults.filter(form => form.isSecureAction).length,
    insecureFormsCount: formResults.filter(form => !form.isSecureAction).length
  };
}

/**
 * Analyze links using Cheerio
 * @param {object} $ - Cheerio instance with loaded HTML
 * @param {string} baseUrl - Base URL for resolving relative links
 * @returns {object} - Link analysis results
 */
function analyzeLinks($, baseUrl) {
  const links = $('a[href]');
  const internalLinks = new Set();
  const externalLinks = new Set();
  const insecureLinks = new Set();
  const baseUrlObj = new URL(baseUrl);
  const baseDomain = baseUrlObj.hostname;
  
  links.each((i, link) => {
    const href = $(link).attr('href');
    if (!href || href.startsWith('#') || href.startsWith('javascript:')) {
      return;
    }
    
    try {
      // Resolve relative URLs
      const absoluteUrl = new URL(href, baseUrl).href;
      const linkUrlObj = new URL(absoluteUrl);
      
      if (linkUrlObj.hostname === baseDomain) {
        internalLinks.add(absoluteUrl);
      } else {
        externalLinks.add(absoluteUrl);
      }
      
      // Check for insecure links (HTTP on an HTTPS site)
      if (baseUrlObj.protocol === 'https:' && linkUrlObj.protocol === 'http:') {
        insecureLinks.add(absoluteUrl);
      }
    } catch (error) {
      // Invalid URL, just ignore
    }
  });
  
  return {
    total: links.length,
    internal: {
      count: internalLinks.size,
      urls: Array.from(internalLinks)
    },
    external: {
      count: externalLinks.size,
      urls: Array.from(externalLinks)
    },
    insecure: {
      count: insecureLinks.size,
      urls: Array.from(insecureLinks)
    }
  };
}

/**
 * Basic analysis of content security using Cheerio
 * @param {object} $ - Cheerio instance with loaded HTML
 * @returns {object} - Content security analysis
 */
function analyzeContentSecurityBasic($) {
  const results = {
    iframes: [],
    externalScripts: [],
    externalStyles: [],
    dataUris: [],
    inlineScripts: $('script:not([src])').length,
    inlineStyles: $('style').length,
    findings: []
  };
  
  // Check iframes
  $('iframe').each((i, iframe) => {
    const $iframe = $(iframe);
    const src = $iframe.attr('src') || '';
    const sandbox = $iframe.attr('sandbox');
    
    results.iframes.push({
      src,
      hasSandbox: !!sandbox,
      sandboxValue: sandbox || null
    });
    
    if (src && !sandbox) {
      results.findings.push('Iframe without sandbox attribute: ' + src);
    }
  });
  
  // Check external scripts
  $('script[src]').each((i, script) => {
    const src = $(script).attr('src') || '';
    if (src.startsWith('http')) {
      results.externalScripts.push(src);
    }
    
    if (src.startsWith('data:')) {
      results.dataUris.push({
        type: 'script',
        uri: src.substring(0, 50) + '...'
      });
      results.findings.push('Script using data URI (potential security risk)');
    }
  });
  
  // Check external styles
  $('link[rel="stylesheet"][href]').each((i, style) => {
    const href = $(style).attr('href') || '';
    if (href.startsWith('http')) {
      results.externalStyles.push(href);
    }
    
    if (href.startsWith('data:')) {
      results.dataUris.push({
        type: 'style',
        uri: href.substring(0, 50) + '...'
      });
      results.findings.push('Stylesheet using data URI (potential security risk)');
    }
  });
  
  // Check for eval in inline scripts
  $('script:not([src])').each((i, script) => {
    const content = $(script).html() || '';
    if (content.includes('eval(') || content.includes('document.write(')) {
      results.findings.push('Potentially unsafe JavaScript: using eval() or document.write()');
    }
  });
  
  return results;
}

/**
 * Basic XSS vulnerability detection
 * @param {object} $ - Cheerio instance with loaded HTML
 * @param {string} baseUrl - Base URL for constructing test URLs
 * @returns {object} - XSS detection results
 */
function detectXssVulnerabilities($, baseUrl) {
  const results = {
    reflectionPoints: [],
    urlParameters: [],
    findings: []
  };
  
  // Extract URL parameters for potential reflection testing
  try {
    const url = new URL(baseUrl);
    url.searchParams.forEach((value, name) => {
      results.urlParameters.push({
        name,
        value
      });
    });
  } catch (error) {
    // Invalid URL, just ignore
  }
  
  // Basic check for reflection points (warning: false positives likely)
  // In a real implementation, this would require active testing with unique markers
  
  // Note: This is a very simplistic passive detection approach
  // Real XSS detection requires active testing which should only be done with permission
  
  // Look for reflected parameters in content
  results.urlParameters.forEach(param => {
    const regex = new RegExp(escapeRegExp(param.value), 'i');
    
    // Check if parameter is reflected in HTML
    const html = $.html();
    if (regex.test(html)) {
      results.reflectionPoints.push({
        parameter: param.name,
        value: param.value,
        reflection: 'HTML body'
      });
      
      results.findings.push(`Potential reflection point: parameter "${param.name}" found in page content`);
    }
  });
  
  // Check for common XSS sinks
  $('script:not([src])').each((i, script) => {
    const content = $(script).html() || '';
    
    const dangerousFunctions = [
      'document.write(',
      'innerHTML',
      'outerHTML',
      'insertAdjacentHTML',
      'eval(',
      'setTimeout(',
      'setInterval('
    ];
    
    dangerousFunctions.forEach(func => {
      if (content.includes(func)) {
        results.findings.push(`Potentially unsafe JavaScript sink: ${func}`);
      }
    });
  });
  
  return results;
}

/**
 * Helper function to escape regex special chars
 * @param {string} string - String to escape
 * @returns {string} - Escaped string
 */
function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Calculate overall web security score
 * @param {object} results - Scan results
 * @returns {object} - Security score information
 */
function calculateWebSecurityScore(results) {
  let totalScore = 0;
  let maxScore = 0;
  const breakdown = {};
  
  // SSL score (0-25)
  if (results.ssl && !results.ssl.error) {
    const sslScore = results.ssl.analysis.score || 0;
    totalScore += sslScore;
    maxScore += 25;
    breakdown.ssl = {
      score: sslScore,
      maxScore: 25
    };
  }
  
  // Headers score (0-25)
  if (results.headers && !results.headers.error) {
    const headerScore = results.headers.analysis.score || 0;
    totalScore += headerScore;
    maxScore += 25;
    breakdown.headers = {
      score: headerScore,
      maxScore: 25
    };
  }
  
  // CSP score (0-15)
  if (results.csp && !results.csp.error) {
    const cspScore = results.csp.analysis.score || 0;
    totalScore += cspScore;
    maxScore += 15;
    breakdown.csp = {
      score: cspScore,
      maxScore: 15
    };
  }
  
  // Cookie security score (0-15)
  if (results.cookies && !results.cookies.error) {
    const cookieScore = results.cookies.analysis.score || 0;
    totalScore += cookieScore;
    maxScore += 15;
    breakdown.cookies = {
      score: cookieScore,
      maxScore: 15
    };
  }
  
  // Form security score (0-10)
  if (results.forms) {
    const formCount = results.forms.count;
    const insecureFormCount = results.forms.insecureFormsCount;
    let formScore = 10;
    
    if (formCount > 0) {
      formScore = Math.max(0, 10 - (insecureFormCount / formCount) * 10);
    }
    
    totalScore += formScore;
    maxScore += 10;
    breakdown.forms = {
      score: formScore,
      maxScore: 10
    };
  }
  
  // Content security score (0-10)
  if (results.content && !results.content.error) {
    const findingsCount = results.content.findings.length;
    let contentScore = 10;
    
    if (findingsCount > 0) {
      contentScore = Math.max(0, 10 - findingsCount);
    }
    
    totalScore += contentScore;
    maxScore += 10;
    breakdown.content = {
      score: contentScore,
      maxScore: 10
    };
  }
  
  // Calculate percentage
  const percentageScore = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;
  
  // Determine rating
  let rating;
  if (percentageScore >= 90) {
    rating = 'A+';
  } else if (percentageScore >= 80) {
    rating = 'A';
  } else if (percentageScore >= 70) {
    rating = 'B';
  } else if (percentageScore >= 60) {
    rating = 'C';
  } else if (percentageScore >= 50) {
    rating = 'D';
  } else {
    rating = 'F';
  }
  
  return {
    score: percentageScore,
    rating,
    breakdown
  };
}

module.exports = {
  scanWeb,
  analyzeFormSecurity,
  analyzeLinks,
  analyzeContentSecurityBasic,
  detectXssVulnerabilities
};
