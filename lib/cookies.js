/**
 * Cookie Security Analysis Module
 * Analyzes cookies for security issues and best practices
 */
const axios = require('axios');
const cookie = require('cookie');
const url = require('url');

/**
 * Check cookies for a website
 * @param {string} targetUrl - URL to check
 * @returns {Promise<object>} - Cookie security analysis
 */
async function checkCookies(targetUrl) {
  try {
    // Ensure URL has protocol
    if (!targetUrl.startsWith('http')) {
      targetUrl = `https://${targetUrl}`;
    }

    // Parse the domain from the URL
    const parsedUrl = new url.URL(targetUrl);
    const domain = parsedUrl.hostname;

    // Make a request and capture cookies
    const response = await axios.get(targetUrl, {
      timeout: 10000,
      maxRedirects: 5,
      validateStatus: null,
      headers: {
        'User-Agent': 'secure-web-scanner/1.0.0'
      }
    });

    // Get cookies from response headers
    const cookieHeaders = response.headers['set-cookie'] || [];
    const cookies = [];

    // Parse each cookie
    for (const cookieHeader of cookieHeaders) {
      try {
        // Extract the cookie name=value part
        const cookieParts = cookieHeader.split(';');
        const mainPart = cookieParts[0].trim();
        
        // Parse the cookie attributes
        const parsedCookie = cookie.parse(mainPart);
        const cookieName = Object.keys(parsedCookie)[0];
        const cookieValue = parsedCookie[cookieName];
        
        // Get cookie attributes
        const attributes = {
          secure: cookieHeader.toLowerCase().includes('secure'),
          httpOnly: cookieHeader.toLowerCase().includes('httponly'),
          sameSite: 'None', // Default
          expires: null,
          maxAge: null,
          path: '/',
          domain: null
        };
        
        // Parse additional attributes
        for (let i = 1; i < cookieParts.length; i++) {
          const part = cookieParts[i].trim().toLowerCase();
          
          if (part.startsWith('expires=')) {
            attributes.expires = part.substring(8);
          } else if (part.startsWith('max-age=')) {
            attributes.maxAge = parseInt(part.substring(8), 10);
          } else if (part.startsWith('domain=')) {
            attributes.domain = part.substring(7);
          } else if (part.startsWith('path=')) {
            attributes.path = part.substring(5);
          } else if (part.startsWith('samesite=')) {
            attributes.sameSite = part.substring(9);
          }
        }

        cookies.push({
          name: cookieName,
          value: cookieValue, // Only storing for analysis
          attributes
        });
      } catch (error) {
        // Skip malformed cookies
      }
    }

    return {
      url: targetUrl,
      domain,
      cookies,
      totalCookies: cookies.length,
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
 * Analyze cookies for security best practices
 * @param {object} cookieData - Results from checkCookies
 * @returns {object} - Security analysis
 */
function analyzeCookieSecurity(cookieData) {
  if (cookieData.error) {
    return {
      status: 'error',
      message: cookieData.message,
      issues: [],
      warnings: []
    };
  }

  const issues = [];
  const warnings = [];
  const recommendations = [];

  // No cookies is not necessarily a problem
  if (cookieData.cookies.length === 0) {
    return {
      status: 'secure',
      score: 100,
      percentage: 100,
      issues: [],
      warnings: [],
      recommendations: ['No cookies found']
    };
  }

  // Check each cookie for security issues
  const insecureCookies = [];
  const nonHttpOnlyCookies = [];
  const nonSameSiteCookies = [];
  const sessionCookies = [];

  for (const cookie of cookieData.cookies) {
    const { name, attributes } = cookie;

    // Check for secure flag
    if (!attributes.secure && cookieData.url.startsWith('https')) {
      insecureCookies.push(name);
    }

    // Check for httpOnly flag
    if (!attributes.httpOnly) {
      nonHttpOnlyCookies.push(name);
    }

    // Check for SameSite attribute
    if (attributes.sameSite === 'None' || !attributes.sameSite) {
      nonSameSiteCookies.push(name);
    }

    // Check for session cookies (no expiry)
    if (!attributes.expires && attributes.maxAge === null) {
      sessionCookies.push(name);
    }
  }

  // Add issues based on findings
  if (insecureCookies.length > 0) {
    issues.push(`${insecureCookies.length} cookies missing Secure flag: ${insecureCookies.join(', ')}`);
    recommendations.push('Add Secure flag to all cookies');
  }

  if (nonHttpOnlyCookies.length > 0) {
    warnings.push(`${nonHttpOnlyCookies.length} cookies missing HttpOnly flag: ${nonHttpOnlyCookies.join(', ')}`);
    recommendations.push('Add HttpOnly flag to cookies that don\'t need JavaScript access');
  }

  if (nonSameSiteCookies.length > 0) {
    warnings.push(`${nonSameSiteCookies.length} cookies missing SameSite attribute: ${nonSameSiteCookies.join(', ')}`);
    recommendations.push('Set SameSite=Lax or SameSite=Strict for cookies');
  }

  // Calculate security score
  const maxScore = 100;
  let score = maxScore;

  // Deduct points based on issues
  if (cookieData.cookies.length > 0) {
    const securePercentage = (cookieData.cookies.length - insecureCookies.length) / cookieData.cookies.length;
    const httpOnlyPercentage = (cookieData.cookies.length - nonHttpOnlyCookies.length) / cookieData.cookies.length;
    const sameSitePercentage = (cookieData.cookies.length - nonSameSiteCookies.length) / cookieData.cookies.length;

    // Secure flag is most important (50%)
    score -= (1 - securePercentage) * 50;
    
    // HttpOnly is important (30%)
    score -= (1 - httpOnlyPercentage) * 30;
    
    // SameSite is good practice (20%)
    score -= (1 - sameSitePercentage) * 20;
  }

  // Normalize score between 0-100
  score = Math.max(0, Math.min(100, Math.round(score)));

  return {
    status: issues.length > 0 ? 'issues' : warnings.length > 0 ? 'warnings' : 'secure',
    score,
    percentage: score,
    issues,
    warnings,
    recommendations
  };
}

module.exports = { checkCookies, analyzeCookieSecurity };
