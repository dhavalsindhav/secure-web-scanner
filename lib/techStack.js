const axios = require('axios');
const cheerio = require('cheerio');
const semver = require('semver');
const fs = require('fs');
const path = require('path');

// Regular expressions for technology detection patterns
const TECH_PATTERNS = {
  // Web servers
  servers: [
    { name: 'Apache', regex: /Apache(?:[\\\/]([0-9.]+))?/i },
    { name: 'Nginx', regex: /nginx(?:[\\\/]([0-9.]+))?/i },
    { name: 'IIS', regex: /Microsoft-IIS(?:[\\\/]([0-9.]+))?/i },
    { name: 'LiteSpeed', regex: /LiteSpeed(?:[\\\/]([0-9.]+))?/i },
    { name: 'Cloudflare', regex: /cloudflare/i },
    { name: 'Tomcat', regex: /Tomcat(?:[\\\/]([0-9.]+))?/i },
    { name: 'Node.js', regex: /Node\.js(?:[\\\/]([0-9.]+))?/i },
  ],
  
  // CMS
  cms: [
    { 
      name: 'WordPress',
      regex: /(?:wp-content|wp-includes)/i,
      versionRegex: [
        /<meta name="generator" content="WordPress ([0-9.]+)"/i,
        /\/wp-content\/themes\/[^/]+\/style\.css\?ver=([0-9.]+)/i,
        /\/wp-includes\/js\/wp-emoji-release\.min\.js\?ver=([0-9.]+)/i
      ],
      confidence: 0.9
    },
    { 
      name: 'Drupal', 
      regex: /(?:Drupal\.settings|sites\/all|drupal\.org)/i,
      versionRegex: [
        /<meta name="generator" content="Drupal ([0-9.]+)"/i,
        /data-drupal-selector/i
      ],
      confidence: 0.8
    },
    { 
      name: 'Joomla',
      regex: /(?:\/components\/com_|\/media\/jui\/)/i,
      versionRegex: [
        /<meta name="generator" content="Joomla! ([0-9.]+)"/i,
        /\/media\/jui\/js\/jquery\.min\.js\?([0-9a-z]+)/i
      ],
      confidence: 0.8
    },
    { 
      name: 'Magento',
      regex: /(?:Mage\.Cookies|Magento_|\/skin\/frontend\/)/i,
      versionRegex: [
        /Magento(?:\/|_)([0-9.]+)/i
      ],
      confidence: 0.8
    },
    { 
      name: 'Shopify',
      regex: /(?:cdn\.shopify\.com|shopify\.com\/s\/|Shopify\.theme)/i,
      confidence: 0.9
    },
    { 
      name: 'Ghost',
      regex: /ghost\.org|content="Ghost ([0-9.]+)"|ghost-theme/i,
      versionRegex: [
        /<meta name="generator" content="Ghost ([0-9.]+)"/i
      ],
      confidence: 0.7
    },
    { 
      name: 'PrestaShop', 
      regex: /(?:PrestaShop|\/themes\/_core\/)/i,
      versionRegex: [
        /PrestaShop(?:_)?([0-9.]+)/i
      ],
      confidence: 0.8
    },
    { 
      name: 'Wix',
      regex: /(?:wix\.com|static\.wix\.com|wixstatic\.com)/i,
      confidence: 0.9
    },
    { 
      name: 'Squarespace',
      regex: /(?:squarespace\.com|static1\.squarespace\.com)/i,
      confidence: 0.9
    },
    { 
      name: 'Webflow',
      regex: /(?:webflow\.com|assets-global\.website-files\.com)/i,
      confidence: 0.9
    }
  ],
  
  // JavaScript frameworks
  frameworks: [
    { 
      name: 'React',
      regex: /(?:react\.(?:min\.)?js|react-dom|reactjs|__REACT_DEVTOOLS_GLOBAL_HOOK__|_reactjs)/i,
      versionRegex: [
        /react[@\/-]([0-9.]+)/i,
        /react\.([0-9.]+)\.js/i
      ],
      confidence: 0.8
    },
    { 
      name: 'Vue.js',
      regex: /(?:vue(?:\.min)?\.js|__vue__|Vue\.compile|VueRouter)/i,
      versionRegex: [
        /vue(?:\.min)?\.js.*?([0-9.]+)/i,
        /vue@([0-9.]+)/i
      ],
      confidence: 0.8
    },
    { 
      name: 'Angular',
      regex: /(?:angular(?:\.min)?\.js|ng-app|ng-controller|angular\.js|ngRoute)/i,
      versionRegex: [
        /angular(?:js)?[\/\-\.]([0-9.]+)/i
      ],
      confidence: 0.7
    },
    { 
      name: 'Next.js',
      regex: /(?:__NEXT_DATA__|next\/static|_next\/static|__NEXT_LOADED_PAGES__)/i,
      confidence: 0.9
    },
    { 
      name: 'Nuxt.js',
      regex: /(?:nuxt\.js|__NUXT__|nuxt-link|nuxt__)/i,
      confidence: 0.9
    },
    { 
      name: 'Svelte',
      regex: /(?:svelte-[a-z0-9]+|__SVELTE|svelte3)/i,
      confidence: 0.8
    },
    { 
      name: 'Ember.js',
      regex: /(?:ember(?:\.min)?\.js|Ember\.Application|_ember-meta_|EmberENV)/i,
      versionRegex: [
        /ember(?:\.min)?\.js.*?([0-9.]+)/i
      ],
      confidence: 0.7
    }
  ],
  
  // JavaScript libraries
  javascript: [
    { 
      name: 'jQuery',
      regex: /(?:jquery(?:\.min)?\.js|jQuery|\$\.fn\.jquery)/i,
      versionRegex: [
        /jquery[\/\-\.]([0-9.]+)(?:\.min)?\.js/i,
        /jquery['|"]?\s*:\s*['|"]([0-9.]+)['|"]/i
      ],
      confidence: 0.8
    },
    { 
      name: 'Bootstrap',
      regex: /(?:bootstrap(?:\.min)?\.(?:js|css)|bootstrap-datepicker)/i,
      versionRegex: [
        /bootstrap[\/\-\.]([0-9.]+)(?:\.min)?\.(?:js|css)/i
      ],
      confidence: 0.7
    },
    { 
      name: 'Tailwind CSS',
      regex: /(?:tailwind(?:\.min)?\.css|tailwindcss|__tailwind|tailwind-|class="[^"]*(?:px-|py-|text-|bg-|grid-|flex-|border-|rounded-))/i,
      confidence: 0.7
    },
    { 
      name: 'GSAP',
      regex: /(?:gsap(?:\.min)?\.js|TweenMax|TweenLite|TimelineMax|gsap\.)/i,
      versionRegex: [
        /gsap[\/\-\.]([0-9.]+)(?:\.min)?\.js/i
      ],
      confidence: 0.7
    },
    { 
      name: 'Lodash',
      regex: /(?:lodash(?:\.min)?\.js|lodash\.core|_\.VERSION)/i,
      versionRegex: [
        /lodash@([0-9.]+)/i,
        /lodash[\/\-\.]([0-9.]+)(?:\.min)?\.js/i
      ],
      confidence: 0.7
    },
    { 
      name: 'Moment.js',
      regex: /(?:moment(?:\.min)?\.js|moment\.locale)/i,
      versionRegex: [
        /moment[\/\-\.]([0-9.]+)(?:\.min)?\.js/i
      ],
      confidence: 0.7
    },
    { 
      name: 'D3.js',
      regex: /(?:d3(?:\.min)?\.js|d3\.select|d3\.scale)/i,
      versionRegex: [
        /d3[\/\-\.]v?([0-9.]+)(?:\.min)?\.js/i
      ],
      confidence: 0.7
    },
    { 
      name: 'Alpine.js',
      regex: /(?:alpine(?:\.min)?\.js|x-data|x-bind|x-on|x-show|x-transition)/i,
      confidence: 0.8
    },
    { 
      name: 'Axios',
      regex: /(?:axios(?:\.min)?\.js|axios\.get|axios\.post)/i,
      versionRegex: [
        /axios[\/\-\.]([0-9.]+)(?:\.min)?\.js/i
      ],
      confidence: 0.7
    }
  ],
  
  // Security technologies
  security: [
    { name: 'Cloudflare', regex: /cloudflare-app|cloudflare\.com/i, confidence: 0.9 },
    { name: 'reCAPTCHA', regex: /google\.com\/recaptcha|recaptcha\.net\/recaptcha/i, confidence: 0.9 },
    { name: 'hCaptcha', regex: /hcaptcha\.com\/captcha/i, confidence: 0.9 },
    { name: 'Imperva/Incapsula', regex: /incapsula|impervadns|visitorIPTracker/i, confidence: 0.8 },
    { name: 'Akamai', regex: /akamai|akam\/|akamaihd\.net/i, confidence: 0.8 },
    { name: 'Sucuri', regex: /sucuri\/|sucuri\.net/i, confidence: 0.8 },
    { name: 'Fastly', regex: /fastly|FASTLY/i, confidence: 0.7 },
    { name: 'Subresource Integrity', regex: /<(?:link|script)[^>]+integrity=/i, confidence: 0.9 },
    { name: 'Content Security Policy', regex: /content-security-policy:/i, confidence: 0.9 }
  ],
  
  // Analytics and tracking
  analytics: [
    { name: 'Google Analytics', regex: /google-analytics\.com\/analytics\.js|ga\.js|gtag|googletagmanager\.com/i, confidence: 0.9 },
    { name: 'Google Tag Manager', regex: /googletagmanager\.com|gtm\.js/i, confidence: 0.9 },
    { name: 'Matomo/Piwik', regex: /matomo\.js|piwik\.js|_paq/i, confidence: 0.8 },
    { name: 'HotJar', regex: /hotjar\.com|hjLaunchEditor/i, confidence: 0.8 },
    { name: 'Mixpanel', regex: /mixpanel\.com|mixpanel\.init/i, confidence: 0.7 },
    { name: 'Heap', regex: /heap-[0-9]+\.js/i, confidence: 0.7 },
    { name: 'Facebook Pixel', regex: /connect\.facebook\.net.*\/fbevents\.js|fbq\(/i, confidence: 0.8 }
  ],
  
  // Web APIs and features
  features: [
    { name: 'Service Worker', regex: /navigator\.serviceWorker|serviceWorker\.register/i, confidence: 0.8 },
    { name: 'Web Assembly', regex: /WebAssembly|wasm/i, confidence: 0.7 },
    { name: 'localStorage/sessionStorage', regex: /localStorage|sessionStorage/i, confidence: 0.6 },
    { name: 'IndexedDB', regex: /indexedDB|IDBDatabase/i, confidence: 0.7 },
    { name: 'WebSockets', regex: /WebSocket|wss:\/\//i, confidence: 0.7 },
    { name: 'WebRTC', regex: /RTCPeerConnection|getUserMedia/i, confidence: 0.7 },
    { name: 'Push API', regex: /pushManager|PushSubscription/i, confidence: 0.8 }
  ],
  
  // Databases and backends
  backend: [
    { name: 'PHP', regex: /(?:\.php(?:\?|$)|X-Powered-By: PHP|PHPSESSID)/i, confidence: 0.8 },
    { name: 'ASP.NET', regex: /(?:\.aspx(?:\?|$)|__VIEWSTATE|__EVENTVALIDATION|ASP\.NET|Microsoft ASP.NET)/i, confidence: 0.8 },
    { name: 'Ruby on Rails', regex: /(?:\.rb$|<meta content="authenticity_token"|csrf-param="authenticity_token")/i, confidence: 0.7 },
    { name: 'Django', regex: /(?:csrfmiddlewaretoken|<meta name="robots" content="NONE,NOARCHIVE")/i, confidence: 0.7 },
    { name: 'Express.js', regex: /(?:Express|X-Powered-By: Express)/i, confidence: 0.7 },
    { name: 'Laravel', regex: /(?:laravel_session|XSRF-TOKEN=|X-XSRF-TOKEN)/i, confidence: 0.8 },
    { name: 'GraphQL', regex: /(?:\/graphql|ApolloClient|__typename)/i, confidence: 0.8 },
    { name: 'MongoDB', regex: /(?:mongodb:\/\/|MongoDB)/i, confidence: 0.6 }
  ]
};

// Known security vulnerabilities database (sample entries)
const KNOWN_VULNERABILITIES = {
  'jQuery': [
    { 
      versions: '<1.9.0', 
      severity: 'High',
      description: 'jQuery before 1.9.0 is vulnerable to XSS attacks via .html(), .append() and other DOM manipulation methods',
      cve: 'CVE-2012-6708',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2012-6708'
    },
    { 
      versions: '<3.5.0', 
      severity: 'Medium',
      description: 'jQuery before 3.5.0 is vulnerable to XSS via proper HTML escaping',
      cve: 'CVE-2020-11023',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-11023'
    },
    { 
      versions: '<3.6.0', 
      severity: 'Medium',
      description: 'jQuery before 3.6.0 is vulnerable to XSS via HTML parsing',
      cve: 'CVE-2022-31160',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-31160'
    },
  ],
  'Bootstrap': [
    { 
      versions: '<3.4.1', 
      severity: 'Medium',
      description: 'XSS vulnerability in Bootstrap\'s tooltip/popover components',
      cve: 'CVE-2019-8331',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2019-8331'
    },
    { 
      versions: '<4.3.1', 
      severity: 'Medium',
      description: 'XSS vulnerability in Bootstrap\'s data-template attribute',
      cve: 'CVE-2019-11358',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2019-11358'
    },
    { 
      versions: '<5.0.0', 
      severity: 'Low',
      description: 'Cross-site scripting vulnerability in tooltip component',
      cve: 'CVE-2020-24020',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-24020'
    },
  ],
  'WordPress': [
    { 
      versions: '<5.8.3', 
      severity: 'High',
      description: 'SQL injection vulnerability in WP_Query',
      cve: 'CVE-2022-21661',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-21661'
    },
    { 
      versions: '<5.9.2', 
      severity: 'Critical',
      description: 'Cross-site scripting vulnerability in many WordPress themes',
      cve: 'CVE-2022-0898',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-0898'
    },
    { 
      versions: '<6.0.2', 
      severity: 'Critical',
      description: 'Authenticated SQL injection vulnerability',
      cve: 'CVE-2022-3590',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-3590'
    },
  ],
  'Lodash': [
    {
      versions: '<4.17.21',
      severity: 'High',
      description: 'Command injection vulnerability in Lodash',
      cve: 'CVE-2021-23337',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337'
    },
    {
      versions: '<4.17.12',
      severity: 'High',
      description: 'Prototype pollution vulnerability in Lodash',
      cve: 'CVE-2019-10744',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2019-10744'
    }
  ],
  'Moment.js': [
    {
      versions: '<2.29.2',
      severity: 'Medium',
      description: 'Regular expression denial of service vulnerability',
      cve: 'CVE-2022-24785',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-24785'
    }
  ],
  'Angular': [
    {
      versions: '<1.8.0',
      severity: 'High',
      description: 'Cross-site scripting vulnerability in Angular.js',
      cve: 'CVE-2020-7676',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-7676'
    },
    {
      versions: '<12.0.5',
      severity: 'Medium',
      description: 'Cross-site scripting vulnerability in Angular',
      cve: 'CVE-2021-39154',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-39154'
    }
  ],
  'React': [
    {
      versions: '<16.13.1',
      severity: 'Medium',
      description: 'Cross-site scripting vulnerability due to improper input validation',
      cve: 'CVE-2020-7422',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-7422'
    }
  ],
  'Axios': [
    {
      versions: '<0.21.1',
      severity: 'High',
      description: 'Server-side request forgery vulnerability',
      cve: 'CVE-2020-28168',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-28168'
    }
  ],
  'Nginx': [
    {
      versions: '<1.20.0',
      severity: 'Medium',
      description: 'Information disclosure vulnerability in resolver',
      cve: 'CVE-2021-23017',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017'
    }
  ],
  'Apache': [
    {
      versions: '<2.4.48',
      severity: 'High',
      description: 'Path traversal and file disclosure vulnerability',
      cve: 'CVE-2021-41773',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773'
    }
  ]
  // More vulnerability entries can be added here
};

/**
 * Check a detected technology version against known vulnerabilities
 * @param {string} name - Technology name
 * @param {string} version - Detected version
 * @returns {array} - List of vulnerabilities
 */
function checkVulnerabilities(name, version) {
  if (!version || !KNOWN_VULNERABILITIES[name]) {
    return [];
  }

  return KNOWN_VULNERABILITIES[name].filter(vuln => {
    try {
      return semver.satisfies(version, vuln.versions);
    } catch (e) {
      // In case of invalid semver comparison
      return false;
    }
  });
}

/**
 * Extract version from a string using a regex pattern
 * @param {string} data - Text to search in
 * @param {RegExp|Array<RegExp>} versionRegex - Regex pattern(s) to extract version
 * @returns {string|null} - Extracted version or null
 */
function extractVersion(data, versionRegex) {
  if (!data || !versionRegex) return null;
  
  // Handle both single regex and array of regexes
  const patterns = Array.isArray(versionRegex) ? versionRegex : [versionRegex];
  
  for (const regex of patterns) {
    const match = data.match(regex);
    if (match && match[1]) {
      return match[1];
    }
  }
  
  return null;
}

/**
 * Clean version strings to be compatible with semver
 * @param {string} version - Version string to clean
 * @returns {string} - Cleaned version string
 */
function cleanVersion(version) {
  if (!version) return null;
  
  // Remove any non-version characters
  let cleaned = version.replace(/[^0-9.]/g, '');
  
  // Ensure it has at least major.minor.patch format
  const parts = cleaned.split('.');
  while (parts.length < 3) {
    parts.push('0');
  }
  
  // Join with dots and return
  return parts.slice(0, 3).join('.');
}

/**
 * Analyze HTML for meta information
 * @param {string} html - HTML content
 * @returns {object} - Extracted meta information
 */
function analyzeMeta(html) {
  const $ = cheerio.load(html);
  const meta = {};
  
  // Get meta tags
  $('meta').each((i, el) => {
    const name = $(el).attr('name') || $(el).attr('property');
    const content = $(el).attr('content');
    
    if (name && content) {
      meta[name] = content;
    }
  });
  
  return meta;
}

/**
 * Analyze HTTP Headers for technology clues
 * @param {object} headers - HTTP headers
 * @returns {object} - Detected technologies from headers
 */
function analyzeHeaders(headers) {
  const technologies = {};
  
  // Normalize header names to lowercase
  const normalizedHeaders = {};
  Object.keys(headers).forEach(key => {
    normalizedHeaders[key.toLowerCase()] = headers[key];
  });
  
  // Check for server software
  if (normalizedHeaders['server']) {
    technologies.server = normalizedHeaders['server'];
    
    // Try to match server with patterns
    for (const serverPattern of TECH_PATTERNS.servers) {
      const match = normalizedHeaders['server'].match(serverPattern.regex);
      if (match) {
        technologies.serverDetails = {
          name: serverPattern.name,
          version: match[1] || null
        };
        break;
      }
    }
  }
  
  // Check for backend technologies
  if (normalizedHeaders['x-powered-by']) {
    technologies.poweredBy = normalizedHeaders['x-powered-by'];
  }
  
  // Check for security headers
  const securityHeaders = [
    'strict-transport-security',
    'content-security-policy',
    'x-content-type-options',
    'x-frame-options',
    'x-xss-protection',
    'permissions-policy',
    'referrer-policy',
    'feature-policy'
  ];
  
  technologies.securityHeaders = securityHeaders.filter(
    header => normalizedHeaders[header]
  );
  
  // Check for caching headers
  if (normalizedHeaders['cache-control'] || normalizedHeaders['expires']) {
    technologies.caching = true;
  }
  
  // Check for compression
  if (normalizedHeaders['content-encoding']) {
    technologies.compression = normalizedHeaders['content-encoding'];
  }
  
  return technologies;
}

/**
 * Enhanced technology detection function
 * @param {string} url - The URL to check
 * @param {object} options - Detection options
 * @returns {Promise<object>} - Detailed technology stack information
 */
async function detectTechStack(url, options = {}) {  // Default options
  const defaultOptions = {
    detectionLevel: 'standard', // 'basic', 'standard', 'deep'
    timeout: 10000,
    userAgent: 'secure-web-scanner/1.0.1 (https://github.com/dhavalsindhav/secure-web-scanner)',
    checkVulnerabilities: true,
    focusOnVulnerabilities: false, // For prioritizing vulnerability reports
    followRedirects: true
  };
  
  const detectionOptions = { ...defaultOptions, ...options };
  
  // Ensure URL has a protocol
  if (!url.startsWith('http')) {
    url = 'https://' + url;
  }
  
  try {
    // Fetch page content with advanced options
    const response = await axios.get(url, {
      timeout: detectionOptions.timeout,
      maxRedirects: detectionOptions.followRedirects ? 5 : 0,
      validateStatus: null, // Accept all status codes
      headers: {
        'User-Agent': detectionOptions.userAgent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
      }
    });

    const { headers, data, status } = response;
    const isHtml = typeof data === 'string' && (
      data.includes('<!DOCTYPE html>') || 
      data.includes('<html') || 
      headers['content-type']?.includes('text/html')
    );
    
    // Initialize tech stack object with more comprehensive structure
    const techStack = {
      server: { software: null, version: null },
      backend: [],
      cms: { name: null, version: null, confidence: 0 },
      frameworks: [],
      javascript: [],
      security: [],
      analytics: [],
      features: [],
      fonts: [],
      hosting: null,
      vulnerabilities: []
    };
    
    // Analyze HTTP headers
    const headerTech = analyzeHeaders(headers);
    
    // Extract server info from headers
    if (headerTech.serverDetails) {
      techStack.server = headerTech.serverDetails;
    } else if (headers['server']) {
      techStack.server.software = headers['server'];
    }
    
    if (headers['x-powered-by']) {
      techStack.backend.push({
        name: headers['x-powered-by'],
        confidence: 0.9
      });
    }
    
    // Extract schema.org metadata if present
    if (isHtml) {
      // Use cheerio for HTML parsing
      const $ = cheerio.load(data);
      const meta = analyzeMeta(data);
      
      // Check for generator meta tags (CMS identification)
      if (meta.generator) {
        if (/wordpress/i.test(meta.generator)) {
          const versionMatch = meta.generator.match(/WordPress ([0-9.]+)/i);
          techStack.cms = {
            name: 'WordPress',
            version: versionMatch ? cleanVersion(versionMatch[1]) : null,
            confidence: 0.95
          };
        } else if (/drupal/i.test(meta.generator)) {
          const versionMatch = meta.generator.match(/Drupal ([0-9.]+)/i);
          techStack.cms = {
            name: 'Drupal',
            version: versionMatch ? cleanVersion(versionMatch[1]) : null,
            confidence: 0.95
          };
        } else if (/joomla/i.test(meta.generator)) {
          const versionMatch = meta.generator.match(/Joomla! ([0-9.]+)/i);
          techStack.cms = {
            name: 'Joomla',
            version: versionMatch ? cleanVersion(versionMatch[1]) : null,
            confidence: 0.95
          };
        } else {
          techStack.cms = {
            name: meta.generator,
            version: null,
            confidence: 0.7
          };
        }
      }
      
      // Detect technology via patterns
      for (const categoryName in TECH_PATTERNS) {
        const category = TECH_PATTERNS[categoryName];
        
        for (const tech of category) {
          if (tech.regex.test(data)) {
            // Extract version if possible
            let version = null;
            if (tech.versionRegex) {
              version = extractVersion(data, tech.versionRegex);
              if (version) {
                version = cleanVersion(version);
              }
            }
            
            // Add to the correct category
            switch (categoryName) {
              case 'cms':
                // Only overwrite if confidence is higher or not yet set
                if (!techStack.cms.name || tech.confidence > techStack.cms.confidence) {
                  techStack.cms = {
                    name: tech.name,
                    version: version,
                    confidence: tech.confidence
                  };
                }
                break;
              
              case 'frameworks':
                if (!techStack.frameworks.some(f => f.name === tech.name)) {
                  techStack.frameworks.push({
                    name: tech.name,
                    version: version,
                    confidence: tech.confidence
                  });
                }
                break;
              
              case 'javascript':
                if (!techStack.javascript.some(j => j.name === tech.name)) {
                  techStack.javascript.push({
                    name: tech.name,
                    version: version,
                    confidence: tech.confidence
                  });
                  
                  // Check for vulnerabilities if version is detected
                  if (detectionOptions.checkVulnerabilities && version) {
                    const vulns = checkVulnerabilities(tech.name, version);
                    if (vulns && vulns.length > 0) {
                      vulns.forEach(vuln => {
                        techStack.vulnerabilities.push({
                          technology: tech.name,
                          version: version,
                          ...vuln
                        });
                      });
                    }
                  }
                }
                break;
              
              case 'security':
                if (!techStack.security.some(s => s.name === tech.name)) {
                  techStack.security.push({
                    name: tech.name,
                    confidence: tech.confidence
                  });
                }
                break;
              
              case 'analytics':
                if (!techStack.analytics.some(a => a.name === tech.name)) {
                  techStack.analytics.push({
                    name: tech.name,
                    confidence: tech.confidence
                  });
                }
                break;
              
              case 'features':
                if (!techStack.features.some(f => f.name === tech.name)) {
                  techStack.features.push({
                    name: tech.name,
                    confidence: tech.confidence
                  });
                }
                break;
              
              case 'backend':
                if (!techStack.backend.some(b => b.name === tech.name)) {
                  techStack.backend.push({
                    name: tech.name,
                    confidence: tech.confidence
                  });
                }
                break;
            }
          }
        }
      }
      
      // Extract fonts
      $('link[rel="stylesheet"][href*="fonts.googleapis.com"]').each((i, el) => {
        const href = $(el).attr('href');
        const fontMatch = href.match(/family=([^&:]+)/i);
        if (fontMatch && fontMatch[1]) {
          const fontFamily = fontMatch[1].replace(/\+/g, ' ');
          techStack.fonts.push(fontFamily);
        }
      });
      
      // Look for icon fonts
      if (data.includes('font-awesome')) {
        techStack.fonts.push('Font Awesome');
      }
      if (data.includes('material-icons')) {
        techStack.fonts.push('Material Icons');
      }
      
      // Deduplicate fonts
      techStack.fonts = [...new Set(techStack.fonts)];
    }
    
    // Add a summary of security features
    techStack.securityFeatures = {
      hasHttps: url.startsWith('https://'),
      hasCsp: headers['content-security-policy'] !== undefined,
      hasHsts: headers['strict-transport-security'] !== undefined,
      hasXfo: headers['x-frame-options'] !== undefined,
      hasXcto: headers['x-content-type-options'] !== undefined,
      hasXss: headers['x-xss-protection'] !== undefined
    };
    
    // Analyze hosting provider based on headers and IPs
    if (headers['server'] && headers['server'].includes('cloudflare')) {
      techStack.hosting = 'Cloudflare';
    } else if (headers['server'] && headers['server'].includes('AmazonS3')) {
      techStack.hosting = 'AWS S3';
    } else if (headers['x-served-by'] && headers['x-served-by'].includes('Netlify')) {
      techStack.hosting = 'Netlify';
    } else if (headers['server'] && headers['server'].includes('GitHub.com')) {
      techStack.hosting = 'GitHub Pages';
    } else if (headers['x-goog-resource-state']) {
      techStack.hosting = 'Google Cloud';
    } else if (headers['x-azure-ref']) {
      techStack.hosting = 'Azure';
    } else if (headers['x-vercel-id']) {
      techStack.hosting = 'Vercel';
    }
    
    // Add recommendations based on findings
    const recommendations = [];
    
    // Security recommendations
    if (!techStack.securityFeatures.hasHttps) {
      recommendations.push({
        type: 'security',
        severity: 'High',
        message: 'Enable HTTPS to secure data transmission'
      });
    }
    
    if (!techStack.securityFeatures.hasCsp) {
      recommendations.push({
        type: 'security',
        severity: 'Medium',
        message: 'Implement Content Security Policy to prevent XSS attacks'
      });
    }
    
    if (!techStack.securityFeatures.hasHsts) {
      recommendations.push({
        type: 'security',
        severity: 'Medium',
        message: 'Enable Strict-Transport-Security header for improved HTTPS security'
      });
    }
    
    // Vulnerability recommendations
    if (techStack.vulnerabilities.length > 0) {
      techStack.vulnerabilities.forEach(vuln => {
        recommendations.push({
          type: 'vulnerability',
          severity: vuln.severity,
          message: `Update ${vuln.technology} from version ${vuln.version} to fix ${vuln.description} (${vuln.cve})`
        });
      });
    }
    
    // Add recommendations to final output
    techStack.recommendations = recommendations;
    
    // Add summary score based on security features and vulnerabilities
    let securityScore = 100;
    
    // Deduct points for missing security features
    if (!techStack.securityFeatures.hasHttps) securityScore -= 20;
    if (!techStack.securityFeatures.hasCsp) securityScore -= 15;
    if (!techStack.securityFeatures.hasHsts) securityScore -= 10;
    if (!techStack.securityFeatures.hasXfo) securityScore -= 10;
    if (!techStack.securityFeatures.hasXcto) securityScore -= 5;
    if (!techStack.securityFeatures.hasXss) securityScore -= 5;
    
    // Deduct points for vulnerabilities based on severity
    techStack.vulnerabilities.forEach(vuln => {
      switch(vuln.severity) {
        case 'Critical':
          securityScore -= 20;
          break;
        case 'High':
          securityScore -= 15;
          break;
        case 'Medium':
          securityScore -= 10;
          break;
        case 'Low':
          securityScore -= 5;
          break;
      }
    });
    
    // Ensure score doesn't go below 0
    // If focusing on vulnerabilities, prioritize that in the score calculation
    if (detectionOptions.focusOnVulnerabilities && techStack.vulnerabilities && techStack.vulnerabilities.length > 0) {
      // Calculate a separate vulnerability score 
      let vulnScore = 100;
      techStack.vulnerabilities.forEach(vuln => {
        switch(vuln.severity) {
          case 'Critical':
            vulnScore -= 40;
            break;
          case 'High':
            vulnScore -= 30;
            break;
          case 'Medium':
            vulnScore -= 20;
            break;
          case 'Low':
            vulnScore -= 10;
            break;
        }
      });
      
      // Emphasize vulnerabilities more in the final score
      securityScore = Math.max(0, (securityScore + Math.max(0, vulnScore)) / 2);
    }
    
    techStack.securityScore = Math.max(0, securityScore);

    return {
      url,
      status,
      techStack,
      error: false
    };
  } catch (err) {
    return {
      error: true,
      message: err.message,
      url
    };
  }
}

/**
 * Analyze technology stack for security issues
 * @param {object} techData - Technology data from detectTechStack
 * @returns {object} - Security analysis results
 */
function analyzeTechStackSecurity(techData) {
  if (techData.error) {
    return {
      status: 'error',
      message: techData.message,
      score: 0,
      percentage: 0,
      issues: [],
      warnings: [],
      recommendations: []
    };
  }

  const { techStack } = techData;
  const analysis = {
    status: 'secure',
    score: techStack.securityScore || 100,
    percentage: techStack.securityScore || 100,
    issues: [],
    warnings: [],
    recommendations: [],
    vulnerabilities: techStack.vulnerabilities || []
  };
  
  // Add vulnerabilities as critical issues
  if (techStack.vulnerabilities && techStack.vulnerabilities.length > 0) {
    techStack.vulnerabilities.forEach(vuln => {
      const vulnMessage = `${vuln.technology} ${vuln.version} has ${vuln.severity.toLowerCase()} vulnerability: ${vuln.description} (${vuln.cve})`;
      analysis.issues.push(vulnMessage);
      
      const fixMessage = `Update ${vuln.technology} from version ${vuln.version} to fix ${vuln.description}`;
      analysis.recommendations.push(fixMessage);
    });
  }
  
  // Transform recommendations from techStack to standard format
  if (techStack.recommendations && techStack.recommendations.length > 0) {
    techStack.recommendations.forEach(rec => {
      if (rec.severity === 'High' || rec.severity === 'Critical') {
        if (!analysis.issues.some(issue => issue.includes(rec.message))) {
          analysis.issues.push(rec.message);
        }
      } else {
        if (!analysis.warnings.some(warning => warning.includes(rec.message))) {
          analysis.warnings.push(rec.message);
        }
      }
      
      // Only add if not already in recommendations list
      if (!analysis.recommendations.some(r => r.includes(rec.message))) {
        analysis.recommendations.push(rec.message);
      }
    });
  }
  
  // Check for outdated technologies based on common knowledge
  if (techStack.cms && techStack.cms.name === 'WordPress' && 
      techStack.cms.version && parseFloat(techStack.cms.version) < 5.8) {
    const wpWarning = `WordPress version ${techStack.cms.version} is outdated. Consider updating to the latest version`;
    if (!analysis.warnings.some(w => w.includes('WordPress version'))) {
      analysis.warnings.push(wpWarning);
    }
    
    const wpRec = `Update WordPress from version ${techStack.cms.version} to the latest version for improved security`;
    if (!analysis.recommendations.some(r => r.includes('Update WordPress'))) {
      analysis.recommendations.push(wpRec);
    }
  }
  
  // Check for jQuery
  const jquery = techStack.javascript && techStack.javascript.find && 
                 techStack.javascript.find(lib => lib && lib.name === 'jQuery');
  if (jquery && jquery.version && parseFloat(jquery.version) < 3.0) {
    const jqWarning = `jQuery version ${jquery.version} is outdated and may have security vulnerabilities`;
    if (!analysis.warnings.some(w => w.includes('jQuery version'))) {
      analysis.warnings.push(jqWarning);
    }
    
    const jqRec = `Update jQuery from version ${jquery.version} to 3.x for improved security`;
    if (!analysis.recommendations.some(r => r.includes('Update jQuery'))) {
      analysis.recommendations.push(jqRec);
    }
  }
  
  // Determine status based on issues and warnings
  if (analysis.issues.length > 0) {
    analysis.status = 'issues';
  } else if (analysis.warnings.length > 0) {
    analysis.status = 'warnings';
  }
  
  return analysis;
}

module.exports = { 
  detectTechStack,
  analyzeTechStackSecurity,
  checkVulnerabilities,
  analyzeMeta,
  analyzeHeaders
};
