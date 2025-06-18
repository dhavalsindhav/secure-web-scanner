const { safeRequire, isBrowser, createUnavailableFeatureProxy } = require('./browser-compatibility');
const puppeteer = safeRequire('puppeteer', createUnavailableFeatureProxy('puppeteer'));
const path = require('path');
const fs = safeRequire('fs', { promises: createUnavailableFeatureProxy('fs.promises') }).promises;

/**
 * Initialize a Puppeteer browser instance
 * @param {Object} options - Browser configuration options
 * @returns {Promise<Browser>} - Puppeteer browser instance
 */
async function initBrowser(options = {}) {
  const defaultOptions = {
    headless: "new", // Use the new headless mode
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--no-first-run',
      '--no-zygote',
      '--disable-gpu'
    ],
    ignoreHTTPSErrors: true, // Useful for security scanning
  };

  const browserOptions = { ...defaultOptions, ...options };
  return await puppeteer.launch(browserOptions);
}

/**
 * Capture a screenshot of the target website
 * @param {string} url - URL to capture
 * @param {string} outputPath - Path to save the screenshot
 * @param {Object} options - Screenshot options
 * @returns {Promise<string>} - Path to saved screenshot
 */
async function captureScreenshot(url, outputPath, options = {}) {
  const browser = await initBrowser();
  try {
    const page = await browser.newPage();
    
    // Set a realistic viewport
    await page.setViewport({ width: 1920, height: 1080 });
    
    // Set user agent to avoid bot detection
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    
    // Navigate to the URL with timeout
    await page.goto(url, { 
      waitUntil: 'networkidle2', 
      timeout: options.timeout || 30000 
    });

    // Create directory if it doesn't exist
    const dir = path.dirname(outputPath);
    await fs.mkdir(dir, { recursive: true }).catch(() => {});
    
    // Prepare screenshot options
    const screenshotOptions = { 
      path: outputPath,
      fullPage: options.fullPage || false,
      type: options.type || 'png'
    };
    
    // Add quality only for JPEG (not PNG)
    if (options.type === 'jpeg') {
      screenshotOptions.quality = options.quality || 80;
    }
    
    // Take screenshot
    await page.screenshot(screenshotOptions);
    
    return outputPath;
  } finally {
    await browser.close();
  }
}

/**
 * Extract all links from a webpage
 * @param {string} url - URL to scan
 * @param {Object} options - Options for filtering links
 * @returns {Promise<Array<string>>} - Array of discovered links
 */
async function extractLinks(url, options = {}) {
  const browser = await initBrowser();
  try {
    const page = await browser.newPage();
    await page.goto(url, { 
      waitUntil: 'networkidle2',
      timeout: options.timeout || 30000 
    });

    // Extract all links from the page
    const links = await page.evaluate((sameDomain) => {
      const allLinks = Array.from(document.querySelectorAll('a')).map(a => a.href);
      
      if (sameDomain) {
        const currentDomain = window.location.hostname;
        return allLinks.filter(link => {
          try {
            return new URL(link).hostname === currentDomain;
          } catch (e) {
            return false;
          }
        });
      }
      
      return allLinks;
    }, options.sameDomain || false);

    // Filter and clean links
    return [...new Set(links)].filter(link => 
      link && 
      link.trim() !== '' && 
      (link.startsWith('http://') || link.startsWith('https://'))
    );
  } finally {
    await browser.close();
  }
}

/**
 * Check for client-side security vulnerabilities
 * @param {string} url - URL to scan
 * @returns {Promise<Object>} - Vulnerability scan results
 */
async function scanClientSideVulnerabilities(url) {
  // Use more reliable browser options for challenging sites
  const browser = await initBrowser({
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-accelerated-2d-canvas',
      '--disable-gpu',
      '--disable-web-security', // Disable CORS for scanning
      '--disable-features=IsolateOrigins,site-per-process' // Disable site isolation for scanning
    ]
  });
  
  try {
    const page = await browser.newPage();
    
    // Set longer timeout for navigation
    page.setDefaultNavigationTimeout(60000);
    page.setDefaultTimeout(60000);
    
    // Collect JavaScript errors
    const jsErrors = [];
    page.on('pageerror', error => {
      jsErrors.push(error.message);
    });
    
    // Collect console logs
    const consoleMessages = [];
    page.on('console', msg => {
      consoleMessages.push({
        type: msg.type(),
        text: msg.text()
      });
    });

    // Track JavaScript libraries and their sources
    const jsLibraries = new Set();
    
    // Set up request handler before enabling interception
    page.on('request', request => {
      try {
        if (request.resourceType() === 'script') {
          const url = request.url();
          if (url.includes('jquery')) jsLibraries.add('jQuery');
          if (url.includes('angular')) jsLibraries.add('Angular');
          if (url.includes('react')) jsLibraries.add('React');
          if (url.includes('vue')) jsLibraries.add('Vue');
          if (url.includes('bootstrap')) jsLibraries.add('Bootstrap');
        }
      
        // Only continue if the request hasn't been handled yet
        if (!request.isInterceptionHandled()) {
          request.continue().catch(() => {});
        }
      } catch (e) {
        // If there's an error in our handler, try to continue the request
        try {
          if (!request.isInterceptionHandled()) {
            request.continue().catch(() => {});
          }
        } catch (innerErr) {
          // Silently fail if we can't continue
        }
      }
    });
    
    // Enable request interception after setting up the handler
    await page.setRequestInterception(true);

    await page.goto(url, { 
      waitUntil: 'networkidle2',
      timeout: 30000
    });

    // Basic client-side security checks
    const securityChecks = await page.evaluate(() => {
      return {
        // Check for insecure mixed content
        mixedContent: {
          hasMixedContent: document.querySelectorAll('img[src^="http:"], script[src^="http:"], link[href^="http:"]').length > 0,
          insecureElements: Array.from(document.querySelectorAll('img[src^="http:"], script[src^="http:"], link[href^="http:"]'))
            .map(el => ({tag: el.tagName.toLowerCase(), src: el.src || el.href}))
            .slice(0, 10) // Limit to first 10 examples
        },
        
        // Check for DOM-based XSS opportunities
        domBasedXssVectors: {
          useOfDocumentWrite: !!document.body.innerHTML.match(/document\.write/i),
          useOfEval: !!document.body.innerHTML.match(/eval\(/i),
          useOfInnerHTML: !!document.body.innerHTML.match(/\.innerHTML\s*=/i),
          useOfSetAttribute: !!document.body.innerHTML.match(/\.setAttribute\(['"]innerHTML['"]|['"]onclick['"]/i)
        },
        
        // Check for sensitive information in the DOM
        sensitiveInfoInDom: {
          possibleApiKeys: !!document.body.innerHTML.match(/(['"]key['"]\s*:|[a-zA-Z0-9_-]+api[a-zA-Z0-9_-]*key[a-zA-Z0-9_-]*['"]|[a-zA-Z0-9_-]+token['"])/i),
          possibleEmailAddresses: !!document.body.innerHTML.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i),
          possiblePhoneNumbers: !!document.body.innerHTML.match(/(\+\d{1,3}[ -]?)?(\(\d{1,4}\)|\d{1,4})[ -]?\d{1,4}[ -]?\d{1,4}[ -]?\d{1,9}/i)
        }
      };
    });

    // Form detection and analysis
    const forms = await page.evaluate(() => {
      return Array.from(document.forms).map(form => {
        // Check if form has proper CSRF protection
        const hasCSRFToken = Array.from(form.elements).some(el => 
          el.name && (el.name.toLowerCase().includes('csrf') || el.name.toLowerCase().includes('token'))
        );
        
        // Check if form is submitting securely
        const isSecureSubmission = form.action && form.action.startsWith('https://');
        
        // Check for sensitive fields
        const hasSensitiveFields = Array.from(form.elements).some(el => 
          el.type === 'password' || 
          (el.name && (
            el.name.toLowerCase().includes('card') || 
            el.name.toLowerCase().includes('credit') ||
            el.name.toLowerCase().includes('ssn') ||
            el.name.toLowerCase().includes('social')
          ))
        );
        
        return {
          id: form.id || 'unnamed-form',
          action: form.action,
          method: form.method.toUpperCase() || 'GET',
          hasCSRFToken,
          isSecureSubmission,
          hasSensitiveFields,
          fieldsCount: form.elements.length,
          hasPasswordField: Array.from(form.elements).some(el => el.type === 'password')
        };
      });
    });

    // Check browser security headers by examining page responses
    const response = await page.goto(url, { waitUntil: 'networkidle2' });
    const securityHeaders = response.headers();

    return {
      jsErrors,
      consoleMessages: consoleMessages.filter(msg => 
        msg.type === 'error' || 
        msg.type === 'warning' ||
        msg.text.toLowerCase().includes('error') ||
        msg.text.toLowerCase().includes('exception') ||
        msg.text.toLowerCase().includes('fail')
      ),
      detectedJsLibraries: Array.from(jsLibraries),
      securityChecks,
      forms,
      securityHeaders
    };
  } finally {
    await browser.close();
  }
}

/**
 * Perform interactive scanning with forms and login attempts
 * @param {string} url - URL to scan
 * @param {Object} credentials - Optional credentials for authentication testing
 * @returns {Promise<Object>} - Results of interactive scanning
 */
async function interactiveScan(url, credentials = null) {
  const browser = await initBrowser();
  try {
    const page = await browser.newPage();
    
    // Track cookies and local storage
    const cookiesAndStorage = {
      cookies: [],
      localStorage: {},
      sessionStorage: {}
    };

    // Set up request handler before enabling interception
    page.on('request', request => {
      try {
        // Only continue if the request hasn't been handled yet
        if (!request.isInterceptionHandled()) {
          request.continue().catch(() => {});
        }
      } catch (e) {
        // If there's an error in our handler, try to continue the request
        try {
          if (!request.isInterceptionHandled()) {
            request.continue().catch(() => {});
          }
        } catch (innerErr) {
          // Silently fail if we can't continue
        }
      }
    });
    
    // Enable request interception after setting up the handler
    await page.setRequestInterception(true);
    
    await page.goto(url, { waitUntil: 'networkidle2' });

    // Test for login functionality if credentials are provided
    let loginAttemptSuccess = false;
    let loginMessages = [];
    if (credentials && credentials.username && credentials.password) {
      try {
        // Find potential login forms
        const loginFormSelector = await page.evaluate(() => {
          // Look for login forms
          const forms = Array.from(document.forms);
          for (const form of forms) {
            const hasPasswordField = Array.from(form.elements).some(el => el.type === 'password');
            if (hasPasswordField) {
              return getSelector(form);
            }
          }
          return null;
          
          // Helper to get selector
          function getSelector(el) {
            if (el.id) return `#${el.id}`;
            if (el.className) {
              const classes = Array.from(el.classList).join('.');
              return `.${classes}`;
            }
            return el.tagName.toLowerCase();
          }
        });
        
        if (loginFormSelector) {
          // Find username and password fields
          await page.evaluate((formSelector, creds) => {
            const form = document.querySelector(formSelector);
            if (!form) return;
            
            const inputs = Array.from(form.elements);
            
            // Find username field
            const usernameField = inputs.find(input => 
              input.type === 'text' || 
              input.type === 'email' || 
              input.name && (
                input.name.includes('user') || 
                input.name.includes('email') || 
                input.name.includes('login')
              )
            );
            
            // Find password field
            const passwordField = inputs.find(input => 
              input.type === 'password'
            );
            
            if (usernameField && passwordField) {
              usernameField.value = creds.username;
              passwordField.value = creds.password;
            }
            
          }, loginFormSelector, credentials);
          
          // Click the submit button
          await Promise.all([
            page.evaluate(formSelector => {
              const form = document.querySelector(formSelector);
              if (!form) return;
              
              // Try to find a submit button
              const submitButton = Array.from(form.elements).find(el => 
                el.type === 'submit' || 
                (el.tagName === 'BUTTON' && !el.type) ||
                (el.tagName === 'BUTTON' && el.type === 'submit')
              );
              
              if (submitButton) {
                submitButton.click();
              } else {
                form.submit();
              }
            }, loginFormSelector),
            page.waitForNavigation({ timeout: 10000 }).catch(() => {})
          ]);
          
          // Check if login was successful (very basic check)
          loginAttemptSuccess = await page.evaluate(() => {
            // Check for common post-login indicators
            const hasLogoutButton = !!document.querySelector('a[href*="logout"]') || 
                                   !!document.querySelector('a[href*="signout"]') ||
                                   !!document.querySelector('button:contains("Logout")') ||
                                   !!document.querySelector('button:contains("Sign out")');
                                   
            const hasProfileSection = !!document.querySelector('a[href*="profile"]') ||
                                     !!document.querySelector('a[href*="account"]') ||
                                     !!document.querySelector('.profile') ||
                                     !!document.querySelector('.account');
                                     
            const noLoginForm = !document.querySelector('form input[type="password"]');
            
            return hasLogoutButton || hasProfileSection || noLoginForm;
          });
          
          // Get cookies after login attempt
          cookiesAndStorage.cookies = await page.cookies();
          
          // Get localStorage after login
          cookiesAndStorage.localStorage = await page.evaluate(() => {
            const items = {};
            for (let i = 0; i < localStorage.length; i++) {
              const key = localStorage.key(i);
              items[key] = localStorage.getItem(key);
            }
            return items;
          });
          
          // Get sessionStorage after login
          cookiesAndStorage.sessionStorage = await page.evaluate(() => {
            const items = {};
            for (let i = 0; i < sessionStorage.length; i++) {
              const key = sessionStorage.key(i);
              items[key] = sessionStorage.getItem(key);
            }
            return items;
          });
          
          loginMessages.push(`Login attempt completed. Success detection: ${loginAttemptSuccess ? 'Likely successful' : 'Likely failed'}`);
        } else {
          loginMessages.push('No login form detected on the page');
        }
      } catch (error) {
        loginMessages.push(`Error during login: ${error.message}`);
      }
    }

    // Analyze session handling and storage usage after interaction
    const sessionAnalysis = await page.evaluate(() => {
      const analysis = {
        localStorage: {
          itemCount: localStorage.length,
          sensitiveDataRisks: false,
          exampleKeys: []
        },
        sessionStorage: {
          itemCount: sessionStorage.length,
          sensitiveDataRisks: false,
          exampleKeys: []
        },
        jwtTokens: {
          found: false,
          storageLocation: null
        }
      };
      
      // Check localStorage
      for (let i = 0; i < localStorage.length && i < 10; i++) {
        const key = localStorage.key(i);
        analysis.exampleKeys.push(key);
        
        const value = localStorage.getItem(key);
        // Check for potentially sensitive data
        if (
          key.toLowerCase().includes('token') ||
          key.toLowerCase().includes('auth') ||
          key.toLowerCase().includes('session') ||
          key.toLowerCase().includes('key') ||
          value.match(/[a-zA-Z0-9_-]{20,}/) // Long string that might be a token
        ) {
          analysis.localStorage.sensitiveDataRisks = true;
          
          // Check for JWT tokens
          if (
            value.match(/^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/) || // JWT pattern
            key.toLowerCase().includes('jwt') ||
            key.toLowerCase().includes('token')
          ) {
            analysis.jwtTokens.found = true;
            analysis.jwtTokens.storageLocation = 'localStorage';
          }
        }
      }
      
      // Check sessionStorage
      for (let i = 0; i < sessionStorage.length && i < 10; i++) {
        const key = sessionStorage.key(i);
        analysis.sessionStorage.exampleKeys.push(key);
        
        const value = sessionStorage.getItem(key);
        // Check for potentially sensitive data
        if (
          key.toLowerCase().includes('token') ||
          key.toLowerCase().includes('auth') ||
          key.toLowerCase().includes('session') ||
          key.toLowerCase().includes('key') ||
          value.match(/[a-zA-Z0-9_-]{20,}/) // Long string that might be a token
        ) {
          analysis.sessionStorage.sensitiveDataRisks = true;
          
          // Check for JWT tokens
          if (
            value.match(/^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/) || // JWT pattern
            key.toLowerCase().includes('jwt') ||
            key.toLowerCase().includes('token')
          ) {
            analysis.jwtTokens.found = true;
            analysis.jwtTokens.storageLocation = 'sessionStorage';
          }
        }
      }
      
      return analysis;
    });

    return {
      url,
      title: await page.title(),
      loginAttempt: credentials ? {
        attempted: true,
        success: loginAttemptSuccess,
        messages: loginMessages
      } : {
        attempted: false
      },
      cookies: cookiesAndStorage.cookies,
      sessionAnalysis,
      securityRisks: {
        sensitiveDataInStorage: sessionAnalysis.localStorage.sensitiveDataRisks || 
                               sessionAnalysis.sessionStorage.sensitiveDataRisks,
        jwtInInsecureStorage: sessionAnalysis.jwtTokens.found && 
                             sessionAnalysis.jwtTokens.storageLocation === 'localStorage',
      }
    };
  } finally {
    await browser.close();
  }
}

/**
 * Analyze content security by examining loaded resources
 * @param {string} url - URL to scan
 * @returns {Promise<Object>} - Content security analysis results
 */
async function analyzeContentSecurity(url) {
  const browser = await initBrowser();
  try {
    const page = await browser.newPage();
    
    // Track all requests
    const requests = [];
    page.on('request', request => {
      requests.push({
        url: request.url(),
        type: request.resourceType(),
        method: request.method()
      });
      request.continue();
    });
    
    // Create tracking structures before enabling interception
    const securityInfo = {
      thirdPartyDomains: new Set(),
      totalRequests: 0,
      resourceTypes: {},
      mainDomain: new URL(url).hostname
    };
    
    // Set up request handler before enabling interception
    page.on('request', request => {
      try {
        const resourceUrl = request.url();
        try {
          const domain = new URL(resourceUrl).hostname;
          if (domain !== securityInfo.mainDomain) {
            securityInfo.thirdPartyDomains.add(domain);
          }
          
          // Count resource types
          const type = request.resourceType();
          securityInfo.resourceTypes[type] = (securityInfo.resourceTypes[type] || 0) + 1;
          
          securityInfo.totalRequests++;
        } catch (e) {
          // Invalid URL, ignore
        }
        
        // Only continue if the request hasn't been handled yet
        if (!request.response() && request.isInterceptionHandled() === false) {
          request.continue().catch(() => {});
        }
      } catch (e) {
        // If there's an error in our handler, try to continue the request
        try {
          if (!request.isInterceptionHandled()) {
            request.continue().catch(() => {});
          }
        } catch (innerErr) {
          // Silently fail if we can't continue
        }
      }
    });
    
    // Enable request interception after setting up the handler
    await page.setRequestInterception(true);
    
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });

    // Extract iframe information
    const iframeInfo = await page.evaluate(() => {
      const iframes = Array.from(document.querySelectorAll('iframe'));
      return iframes.map(iframe => {
        return {
          src: iframe.src,
          sandbox: iframe.sandbox ? iframe.sandbox.value : null,
          hasAllowScripts: iframe.sandbox ? iframe.sandbox.contains('allow-scripts') : false,
          hasAllowSameOrigin: iframe.sandbox ? iframe.sandbox.contains('allow-same-origin') : false
        };
      });
    });

    return {
      url,
      thirdPartyDomains: Array.from(securityInfo.thirdPartyDomains),
      thirdPartyCount: securityInfo.thirdPartyDomains.size,
      totalRequests: securityInfo.totalRequests,
      resourceBreakdown: securityInfo.resourceTypes,
      iframeAnalysis: {
        count: iframeInfo.length,
        details: iframeInfo,
        hasSandboxedIframes: iframeInfo.some(iframe => iframe.sandbox !== null),
        hasUnsandboxedIframes: iframeInfo.some(iframe => iframe.sandbox === null),
        securityRisk: iframeInfo.some(iframe => iframe.hasAllowScripts && iframe.hasAllowSameOrigin)
      }
    };
  } finally {
    await browser.close();
  }
}

module.exports = {
  initBrowser,
  captureScreenshot,
  extractLinks,
  scanClientSideVulnerabilities,
  interactiveScan,
  analyzeContentSecurity
};
