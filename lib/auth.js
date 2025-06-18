/**
 * Authentication Security Module
 * This module provides functionality for analyzing authentication mechanisms
 */

const axios = require('axios');
const cheerio = require('cheerio');
const puppeteer = require('puppeteer');
const chalk = require('chalk');

/**
 * Analyze authentication form security
 * @param {string} url - URL of the login page
 * @param {object} options - Analysis options
 * @returns {Promise<object>} - Analysis results
 */
async function analyzeAuthForm(url, options = {}) {
  try {
    const browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2' });
    
    // Find login forms
    const forms = await page.$$eval('form', forms => {
      return forms.map(form => {
        const passwordFields = form.querySelectorAll('input[type="password"]').length;
        const usernameField = form.querySelector('input[type="text"], input[type="email"]');
        const csrfToken = form.querySelector('input[name="csrf"], input[name="csrf_token"], input[name="_token"]');
        
        return {
          action: form.action,
          method: form.method,
          hasPasswordField: passwordFields > 0,
          hasUsernameField: !!usernameField,
          hasCsrfToken: !!csrfToken,
          isSecure: form.action?.startsWith('https://')
        };
      }).filter(form => form.hasPasswordField); // Only include forms with password fields
    });
    
    const results = {
      url,
      loginForms: forms,
      issues: []
    };
    
    // Analyze forms
    for (let i = 0; i < forms.length; i++) {
      const form = forms[i];
      
      // Check for HTTPS
      if (!form.isSecure) {
        results.issues.push({
          severity: 'HIGH',
          type: 'INSECURE_FORM_SUBMISSION',
          description: 'Login form submits over HTTP instead of HTTPS',
          form: i
        });
      }
      
      // Check for CSRF token
      if (!form.hasCsrfToken) {
        results.issues.push({
          severity: 'MEDIUM',
          type: 'MISSING_CSRF_TOKEN',
          description: 'Login form does not have CSRF protection',
          form: i
        });
      }
    }
    
    // Check for other security headers related to authentication
    const response = await page.goto(url, { waitUntil: 'networkidle2' });
    const headers = response.headers();
    
    if (!headers['x-frame-options']) {
      results.issues.push({
        severity: 'MEDIUM',
        type: 'MISSING_X_FRAME_OPTIONS',
        description: 'X-Frame-Options header is missing, exposing the site to clickjacking attacks'
      });
    }
    
    await browser.close();
    return results;
  } catch (error) {
    console.error(chalk.red(`Error analyzing auth form: ${error.message}`));
    return { url, error: error.message, issues: [] };
  }
}

/**
 * Check authentication methods
 * @param {object} operation - OpenAPI operation
 * @returns {Array<object>} - Auth methods
 */
function checkAuthMethods(operation) {
  const authMethods = [];
  
  if (operation.security) {
    operation.security.forEach(security => {
      Object.keys(security).forEach(name => {
        authMethods.push({ name, scopes: security[name] });
      });
    });
  }
  
  return authMethods;
}

/**
 * Analyze JWT token for security issues
 * @param {string} token - JWT token
 * @returns {object} - Analysis results
 */
function analyzeJwt(token) {
  try {
    const [headerB64, payloadB64, signature] = token.split('.');
    
    if (!headerB64 || !payloadB64 || !signature) {
      throw new Error('Invalid JWT format');
    }
    
    // Parse header and payload
    const headerStr = Buffer.from(headerB64, 'base64').toString();
    const payloadStr = Buffer.from(payloadB64, 'base64').toString();
    const header = JSON.parse(headerStr);
    const payload = JSON.parse(payloadStr);
    
    const results = {
      algorithm: header.alg,
      type: header.typ,
      issuer: payload.iss,
      subject: payload.sub,
      audience: payload.aud,
      expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
      issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
      issues: []
    };
    
    // Check for security issues
    if (header.alg === 'none') {
      results.issues.push({
        severity: 'CRITICAL',
        type: 'NONE_ALGORITHM',
        description: 'JWT uses "none" algorithm, allowing token forgery'
      });
    }
    
    if (header.alg === 'HS256' || header.alg === 'HS384' || header.alg === 'HS512') {
      results.issues.push({
        severity: 'LOW',
        type: 'SYMMETRIC_ALGORITHM',
        description: 'JWT uses symmetric algorithm, suitable only for trusted parties'
      });
    }
    
    if (!payload.exp) {
      results.issues.push({
        severity: 'MEDIUM',
        type: 'NO_EXPIRATION',
        description: 'JWT does not contain an expiration claim (exp)'
      });
    }
    
    return results;
  } catch (error) {
    return { error: error.message, issues: [{ severity: 'HIGH', type: 'INVALID_JWT', description: error.message }] };
  }
}

module.exports = {
  analyzeAuthForm,
  analyzeJwt,
  checkAuthMethods
};
