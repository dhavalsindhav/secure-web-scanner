/**
 * Content Security Policy (CSP) Analysis Module
 * Analyzes CSP headers for security issues and best practices
 */
const axios = require('axios');

// List of CSP directives and their recommended values
const CSP_DIRECTIVES = {
  'default-src': { recommended: ["'self'"], critical: true },
  'script-src': { recommended: ["'self'"], critical: true },
  'style-src': { recommended: ["'self'"], critical: false },
  'img-src': { recommended: ["'self'"], critical: false },
  'connect-src': { recommended: ["'self'"], critical: false },
  'font-src': { recommended: ["'self'"], critical: false },
  'object-src': { recommended: ["'none'"], critical: true },
  'media-src': { recommended: ["'self'"], critical: false },
  'frame-src': { recommended: ["'self'"], critical: true },
  'frame-ancestors': { recommended: ["'none'", "'self'"], critical: true },
  'form-action': { recommended: ["'self'"], critical: true },
  'base-uri': { recommended: ["'self'", "'none'"], critical: true },
  'upgrade-insecure-requests': { recommended: [], critical: false },
  'block-all-mixed-content': { recommended: [], critical: false },
  'require-trusted-types-for': { recommended: ["'script'"], critical: false },
  'trusted-types': { recommended: [], critical: false },
  'sandbox': { recommended: [], critical: false },
  'navigate-to': { recommended: ["'self'"], critical: false },
  'worker-src': { recommended: ["'self'"], critical: false },
  'manifest-src': { recommended: ["'self'"], critical: false },
  'prefetch-src': { recommended: ["'self'"], critical: false },
  'report-to': { recommended: [], critical: false },
  'report-uri': { recommended: [], critical: false }
};

// Risky CSP values
const UNSAFE_CSP_VALUES = [
  "'unsafe-inline'",
  "'unsafe-eval'",
  "'unsafe-hashes'",
  "data:",
  "blob:",
  "*"
];

// Common services used for CSP bypasses
const RISKY_CSP_DOMAINS = [
  'ajax.googleapis.com',
  'cdnjs.cloudflare.com',
  'code.jquery.com',
  'cdn.jsdelivr.net'
];

/**
 * Parse CSP string into object with directives
 * @param {string} cspString - CSP header string
 * @returns {object} - Parsed CSP object
 */
function parseCSP(cspString) {
  if (!cspString) return {};
  
  const cspObj = {};
  const directives = cspString.split(';').map(dir => dir.trim());
  
  for (const directive of directives) {
    if (!directive) continue;
    
    const parts = directive.split(/\s+/);
    const directiveName = parts[0].toLowerCase();
    const directiveValues = parts.slice(1);
    
    cspObj[directiveName] = directiveValues;
  }
  
  return cspObj;
}

/**
 * Check Content Security Policy header for a URL
 * @param {string} targetUrl - URL to check
 * @returns {Promise<object>} - CSP analysis
 */
async function checkCSP(targetUrl) {
  try {
    // Ensure URL has protocol
    if (!targetUrl.startsWith('http')) {
      targetUrl = `https://${targetUrl}`;
    }

    // Make a request and get CSP header
    const response = await axios.get(targetUrl, {
      timeout: 10000,
      maxRedirects: 5,
      validateStatus: null,
      headers: {
        'User-Agent': 'secure-web-scanner/1.0.0'
      }
    });

    // Extract CSP headers
    const headers = response.headers;
    const cspHeader = headers['content-security-policy'] || 
                     headers['content-security-policy-report-only'] || 
                     headers['x-content-security-policy'] || 
                     null;
    
    const reportOnlyHeader = headers['content-security-policy-report-only'] ? true : false;
    
    if (!cspHeader) {
      return {
        url: targetUrl,
        hasCSP: false,
        reportOnly: false,
        cspDirectives: {},
        error: false
      };
    }
    
    // Parse the CSP header
    const parsedCSP = parseCSP(cspHeader);
    
    return {
      url: targetUrl,
      hasCSP: true,
      reportOnly: reportOnlyHeader,
      cspHeader,
      cspDirectives: parsedCSP,
      error: false
    };
  } catch (error) {
    return {
      url: targetUrl,
      error: true,
      message: error.message
    };
  }
}

/**
 * Check if a CSP directive includes potentially risky external domains
 * @param {Array} values - Directive values
 * @returns {Array} - Array of risky domains found
 */
function findRiskyDomains(values) {
  if (!values || !Array.isArray(values)) return [];
  
  const riskyDomains = [];
  for (const value of values) {
    // If it's a domain (not a keyword like 'self', 'none', etc.)
    if (!value.startsWith("'") && !value.startsWith('http') && value !== '*') {
      for (const riskyDomain of RISKY_CSP_DOMAINS) {
        if (value.includes(riskyDomain)) {
          riskyDomains.push(value);
          break;
        }
      }
    }
  }
  return riskyDomains;
}

/**
 * Check for nonce or hash usage in CSP
 * @param {object} cspDirectives - Parsed CSP directives
 * @returns {object} - Nonce and hash usage info
 */
function checkNonceAndHashUsage(cspDirectives) {
  const scriptSrc = cspDirectives['script-src'] || [];
  const styleSrc = cspDirectives['style-src'] || [];
  
  const result = {
    usesNonce: false,
    usesHash: false
  };
  
  for (const value of [...scriptSrc, ...styleSrc]) {
    if (value.startsWith("'nonce-")) {
      result.usesNonce = true;
    }
    if (value.startsWith("'sha256-") || value.startsWith("'sha384-") || value.startsWith("'sha512-")) {
      result.usesHash = true;
    }
  }
  
  return result;
}

/**
 * Generate CSP recommendation with example
 * @param {string} directive - Directive name
 * @param {Array} values - Recommended values
 * @returns {string} - Recommendation with example
 */
function generateCspRecommendation(directive, values = []) {
  let recommendation = '';
  
  switch (directive) {
    case 'default-src':
      recommendation = `Add default-src directive (e.g., default-src 'self';) as a fallback for other fetch directives. This provides a security baseline for all resource types not explicitly defined.`;
      break;
    case 'script-src':
      recommendation = `Add script-src directive (e.g., script-src 'self' 'nonce-{random}' https://trusted-cdn.com;) to control JavaScript sources. This helps prevent XSS attacks by specifying valid script sources.`;
      break;
    case 'object-src':
      recommendation = `Add object-src 'none' directive to block Flash, Java, and other browser plugins which are frequently vectors for attacks.`;
      break;
    case 'style-src':
      recommendation = `Add style-src directive (e.g., style-src 'self' https://trusted-cdn.com;) to control CSS sources. This prevents CSS-based attacks and data exfiltration.`;
      break;
    case 'img-src':
      recommendation = `Add img-src directive (e.g., img-src 'self' https://trusted-cdn.com data:;) to control image sources. This prevents image-based data exfiltration.`;
      break;
    case 'frame-ancestors':
      recommendation = `Add frame-ancestors directive (e.g., frame-ancestors 'none';) to prevent clickjacking attacks. This is more effective than using X-Frame-Options header.`;
      break;
    case 'form-action':
      recommendation = `Add form-action directive (e.g., form-action 'self';) to control where forms can submit to. This helps prevent CSRF attacks.`;
      break;
    case 'base-uri':
      recommendation = `Add base-uri directive (e.g., base-uri 'self';) to restrict base tag URLs. This prevents attackers from changing the base URL and redirecting relative paths.`;
      break;
    case 'upgrade-insecure-requests':
      recommendation = `Add upgrade-insecure-requests directive to automatically upgrade HTTP requests to HTTPS. This ensures all content is loaded securely.`;
      break;
    case 'connect-src':
      recommendation = `Add connect-src directive (e.g., connect-src 'self' https://api.example.com;) to control URLs for fetch, WebSocket, and EventSource connections. This prevents unauthorized data exfiltration.`;
      break; 
    case 'font-src':
      recommendation = `Add font-src directive (e.g., font-src 'self' https://fonts.googleapis.com;) to specify valid sources for loading fonts. This prevents unauthorized font resources from being loaded.`;
      break;
    case 'media-src':
      recommendation = `Add media-src directive (e.g., media-src 'self' https://media.example.com;) to control audio and video sources. This prevents unauthorized media content from being loaded.`;
      break;
    case 'worker-src':
      recommendation = `Add worker-src directive (e.g., worker-src 'self';) to control valid sources for Worker, SharedWorker, or ServiceWorker scripts. This prevents malicious web workers from being loaded.`;
      break;
    default:
      recommendation = `Add ${directive} directive to your CSP to improve security posture.`;
  }
  
  return recommendation;
}

/**
 * Generate a basic starter CSP header for the site
 * @param {string} domain - Domain name
 * @returns {string} - Basic CSP header example
 */
function generateBasicCspExample(domain) {
  return `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; media-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; report-uri https://${domain}/csp-report;`;
}

/**
 * Generate a CSP header with nonce example
 * @returns {string} - CSP header example with nonce
 */
function generateNonceCspExample() {
  return `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random_value_here}'; object-src 'none'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests;`;
}

/**
 * Generate a strict security focused CSP header
 * @returns {string} - Strict security CSP example
 */
function generateStrictCspExample() {
  return `Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; upgrade-insecure-requests; block-all-mixed-content; require-trusted-types-for 'script';`;
}

/**
 * Analyze CSP for security best practices
 * @param {object} cspData - Results from checkCSP
 * @returns {object} - Security analysis
 */
function analyzeCSP(cspData) {
  if (cspData.error) {
    return {
      status: 'error',
      message: cspData.message,
      issues: [],
      warnings: []
    };
  }

  const issues = [];
  const warnings = [];
  const recommendations = [];
  
  // If no CSP is present, that's a major issue
  if (!cspData.hasCSP) {
    issues.push('Content Security Policy (CSP) header not found');
    
    const domain = cspData.url.replace(/^https?:\/\//, '').split('/')[0];
    const basicCspExample = generateBasicCspExample(domain);
    const nonceCspExample = generateNonceCspExample();
    
    recommendations.push('Implement a Content Security Policy header to prevent XSS attacks');
    recommendations.push(`Basic CSP example: ${basicCspExample}`);
    recommendations.push(`CSP with nonce example: ${nonceCspExample}`);
    recommendations.push('Use a CSP generator tool or refer to content-security-policy.com for more examples');
    
    return {
      status: 'issues',
      score: 0,
      percentage: 0,
      issues,
      warnings,
      recommendations,
      examples: {
        basic: basicCspExample,
        withNonce: nonceCspExample
      }
    };
  }
  
  // If CSP is in report-only mode, that's a warning
  if (cspData.reportOnly) {
    warnings.push('CSP is in report-only mode and not enforced');
    recommendations.push('Switch from Content-Security-Policy-Report-Only to Content-Security-Policy for enforcement');
  }

  // Check for missing critical directives
  for (const directive in CSP_DIRECTIVES) {
    if (CSP_DIRECTIVES[directive].critical && !cspData.cspDirectives[directive]) {
      issues.push(`Missing critical CSP directive: ${directive}`);
      recommendations.push(generateCspRecommendation(directive, CSP_DIRECTIVES[directive].recommended));
    }
  }
  
  // Check for unsafe values in directives
  for (const directive in cspData.cspDirectives) {
    const values = cspData.cspDirectives[directive];
    
    for (const unsafeValue of UNSAFE_CSP_VALUES) {
      if (values.includes(unsafeValue)) {
        if (directive === 'script-src' || directive === 'default-src') {
          issues.push(`Unsafe value ${unsafeValue} in ${directive} directive`);
          if (unsafeValue === "'unsafe-inline'") {
            recommendations.push(`Replace ${unsafeValue} in ${directive} with nonces or hashes. Example: ${directive} 'self' 'nonce-random123';`);
          } else if (unsafeValue === "'unsafe-eval'") {
            recommendations.push(`Remove ${unsafeValue} from ${directive} directive and refactor code to avoid eval(), new Function(), etc.`);
          } else if (unsafeValue === "data:") {
            recommendations.push(`Remove ${unsafeValue} from ${directive} directive to prevent data URI injection attacks`);
          } else {
            recommendations.push(`Remove ${unsafeValue} from ${directive} directive and use nonces or hashes instead`);
          }
        } else {
          warnings.push(`Potentially unsafe value ${unsafeValue} in ${directive} directive`);
        }
      }
    }
  }
  
  // Check for wildcard in default-src or script-src
  if (cspData.cspDirectives['default-src'] && 
      cspData.cspDirectives['default-src'].includes('*')) {
    issues.push('Wildcard (*) in default-src directive undermines CSP security');
    recommendations.push(`Replace wildcard in default-src with specific domains. Example: default-src 'self' https://trusted-cdn.com;`);
  }
  
  if (cspData.cspDirectives['script-src'] && 
      cspData.cspDirectives['script-src'].includes('*')) {
    issues.push('Wildcard (*) in script-src directive undermines CSP security');
    recommendations.push(`Replace wildcard in script-src with specific domains. Example: script-src 'self' https://trusted-cdn.com;`);
  }
  
  // Check for risky domains in script-src and default-src
  const scriptSrc = cspData.cspDirectives['script-src'] || [];
  const defaultSrc = cspData.cspDirectives['default-src'] || [];
  
  const riskyScriptDomains = findRiskyDomains(scriptSrc);
  const riskyDefaultDomains = findRiskyDomains(defaultSrc);
  
  if (riskyScriptDomains.length > 0) {
    warnings.push(`Potentially risky domains in script-src: ${riskyScriptDomains.join(', ')}`);
    recommendations.push('Review script-src domains that may be used for CSP bypasses - consider using more restrictive script-src directives');
  }
  
  if (riskyDefaultDomains.length > 0) {
    warnings.push(`Potentially risky domains in default-src: ${riskyDefaultDomains.join(', ')}`);
    recommendations.push('Review default-src domains that may be used for CSP bypasses - consider using more specific directives');
  }
  
  // Check for nonce or hash usage
  const nonceHashUsage = checkNonceAndHashUsage(cspData.cspDirectives);
  if (scriptSrc.includes("'unsafe-inline'") && !nonceHashUsage.usesNonce && !nonceHashUsage.usesHash) {
    issues.push("Using 'unsafe-inline' without nonces or hashes in script-src");
    recommendations.push("Use nonces with 'unsafe-inline' for backward compatibility. Example: script-src 'self' 'unsafe-inline' 'nonce-random123';");
    recommendations.push("Generate unique nonces for each page load using a CSPRNG (e.g., crypto.randomBytes(16).toString('base64'))");
  }
  
  // Check for report-uri and report-to
  const hasReportUri = !!cspData.cspDirectives['report-uri'];
  const hasReportTo = !!cspData.cspDirectives['report-to'];
  
  if (!hasReportUri && !hasReportTo) {
    warnings.push('No reporting mechanism defined in CSP');
    recommendations.push("Add report-to or report-uri directive to collect CSP violation reports. Example: report-uri https://example.com/csp-report");
    recommendations.push("Consider using a CSP reporting service or set up an endpoint to analyze violations");
  }
  
  // Calculate security score
  const maxScore = 100;
  let score = maxScore;
  
  // No CSP = 0 points
  if (!cspData.hasCSP) {
    score = 0;
  } else {
    // CSP in report-only mode = -30
    if (cspData.reportOnly) {
      score -= 30;
    }
    
    // Missing critical directives = -15 each
    const missingCriticalCount = Object.keys(CSP_DIRECTIVES)
      .filter(d => CSP_DIRECTIVES[d].critical && !cspData.cspDirectives[d])
      .length;
    
    score -= missingCriticalCount * 15;
    
    // Unsafe values in script-src or default-src = -20 each
    let unsafeScriptValues = 0;
    
    if (cspData.cspDirectives['script-src']) {
      unsafeScriptValues = UNSAFE_CSP_VALUES.filter(v => 
        cspData.cspDirectives['script-src'].includes(v)
      ).length;
    } else if (cspData.cspDirectives['default-src']) {
      unsafeScriptValues = UNSAFE_CSP_VALUES.filter(v => 
        cspData.cspDirectives['default-src'].includes(v)
      ).length;
    }
    
    score -= unsafeScriptValues * 20;
    
    // Wildcards in important directives = -25
    if (cspData.cspDirectives['default-src'] && 
        cspData.cspDirectives['default-src'].includes('*')) {
      score -= 25;
    }
    
    if (cspData.cspDirectives['script-src'] && 
        cspData.cspDirectives['script-src'].includes('*')) {
      score -= 25;
    }
    
    // No reporting endpoints = -10
    if (!hasReportUri && !hasReportTo) {
      score -= 10;
    }
    
    // Unsafe-inline without nonces or hashes = -15
    if (scriptSrc.includes("'unsafe-inline'") && !nonceHashUsage.usesNonce && !nonceHashUsage.usesHash) {
      score -= 15;
    }
    
    // Using risky domains known for CSP bypass = -10 for each
    score -= (riskyScriptDomains.length + riskyDefaultDomains.length) * 10;
  }
  
  // Normalize score between 0-100
  score = Math.max(0, Math.min(100, Math.round(score)));
  
  // Add directive-specific analysis for detailed reporting
  const directiveAnalysis = {};
  for (const directive in cspData.cspDirectives) {
    directiveAnalysis[directive] = analyzeDirective(directive, cspData.cspDirectives[directive]);
  }
  
  // Add domain-specific CSP recommendation
  if (!cspData.hasCSP) {
    const domain = cspData.url.replace(/^https?:\/\//, '').split('/')[0];
    const cspExample = generateBasicCspExample(domain);
    recommendations.push(`Suggested basic CSP for ${domain}: ${cspExample}`);
  }
  
  return {
    status: issues.length > 0 ? 'issues' : warnings.length > 0 ? 'warnings' : 'secure',
    score,
    percentage: score,
    issues,
    warnings,
    recommendations,
    directiveAnalysis,
    nonceHashUsage,
    examples: {
      basic: generateBasicCspExample(cspData.url.replace(/^https?:\/\//, '').split('/')[0]),
      withNonce: generateNonceCspExample()
    }
  };
}

/**
 * Analyze a specific CSP directive
 * @param {string} name - Directive name
 * @param {Array} values - Directive values
 * @returns {object} - Analysis of the directive
 */
function analyzeDirective(name, values) {
  const analysis = {
    name,
    values,
    issues: [],
    recommendations: []
  };
  
  // Directive-specific checks
  switch (name) {
    case 'script-src':
      if (values.includes("'unsafe-inline'")) {
        analysis.issues.push("Uses 'unsafe-inline' which defeats XSS protections");
      }
      if (values.includes("'unsafe-eval'")) {
        analysis.issues.push("Uses 'unsafe-eval' which allows potentially dangerous code execution");
      }
      if (!values.includes("'self'") && !values.some(v => v === '*')) {
        analysis.recommendations.push("Consider adding 'self' to allow scripts from same origin");
      }
      break;
      
    case 'default-src':
      if (values.includes("'unsafe-inline'")) {
        analysis.issues.push("Uses 'unsafe-inline' in default-src which weakens XSS protections");
      }
      if (values.includes('*')) {
        analysis.issues.push("Uses wildcard (*) which effectively disables CSP protections");
      }
      break;
      
    case 'object-src':
      if (!values.includes("'none'")) {
        analysis.recommendations.push("Consider setting object-src to 'none' to block Flash and other plugins");
      }
      break;
      
    case 'frame-ancestors':
      if (!values.includes("'none'") && !values.includes("'self'")) {
        analysis.issues.push("No restrictive frame-ancestors directive, potential clickjacking risk");
        analysis.recommendations.push("Set frame-ancestors to 'none' or 'self' to prevent clickjacking");
      }
      break;
      
    case 'base-uri':
      if (!values.includes("'none'") && !values.includes("'self'")) {
        analysis.issues.push("No restrictive base-uri directive, potential base tag injection risk");
      }
      break;
  }
  
  return analysis;
}

module.exports = { 
  checkCSP, 
  analyzeCSP, 
  CSP_DIRECTIVES,
  parseCSP, 
  checkNonceAndHashUsage,
  generateCspRecommendation,
  generateBasicCspExample,
  generateNonceCspExample,
  generateStrictCspExample
};
