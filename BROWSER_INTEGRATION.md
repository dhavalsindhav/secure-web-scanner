# Browser Integration Guide

This guide provides instructions for integrating the secure-web-scanner package in browser environments.

## Browser Compatibility

The full secure-web-scanner package is designed primarily for Node.js environments, but we now provide a browser-compatible version with a subset of functionality.

### Available Features in Browser Bundle

The browser bundle includes the following modules:
- HTTP Headers Analysis
- Tech Stack Detection
- Cookie Security Analysis
- Content Security Policy Analysis
- Basic Web Scanning

### Features Not Available in Browser

Due to browser limitations and security restrictions, the following features are NOT available in the browser bundle:
- SSL/TLS Scanning (requires Node.js crypto modules)
- Port Scanning (requires raw socket access)
- WHOIS Lookups (requires Node.js network capabilities)
- Puppeteer Browser Automation (server-side only)
- API Security Scanning (requires server capabilities)
- Cloud Security Scanning (requires server capabilities)
- AI-powered Vulnerability Detection (requires OpenAI API)
- Authentication Analysis (requires Puppeteer)

## Integration Methods

### Using in a Frontend Project

#### Option 1: Use the Pre-built Browser Bundle

```html
<!-- Include the pre-built bundle -->
<script src="path/to/secure-web-scanner.browser.js"></script>
<script>
  // Use the browser-compatible API
  secureWebScanner.browserScan('https://example.com')
    .then(results => console.log(results))
    .catch(err => console.error(err));
</script>
```

#### Option 2: Import in a Modern JS Framework

```javascript
// Import the browser bundle when bundling with webpack/rollup/esbuild
import { browserScan } from 'secure-web-scanner';

// Use the browser-compatible API
browserScan('https://example.com')
  .then(results => {
    console.log('Headers:', results.headers);
    console.log('Tech Stack:', results.techStack);
    console.log('CSP Analysis:', results.cspAnalysis);
  })
  .catch(err => console.error(err));
```

### Building the Browser Bundle

To build the browser bundle yourself:

1. Clone the repository
2. Install dependencies: `npm install`
3. Build the browser bundle: `npm run build:browser`
4. Find the bundle in the `dist` folder

## Handling Node-Only Dependencies

When using bundlers like webpack, Rollup, or esbuild, you might still see warnings about Node.js-only dependencies. Here's how to handle them:

### For webpack

Add the following to your webpack config:

```javascript
module.exports = {
  // ... your other webpack config
  resolve: {
    fallback: {
      // Mark Node.js modules as empty
      fs: false,
      net: false,
      tls: false,
      child_process: false,
      'whois-json': false,
      puppeteer: false,
      'node-port-scanner': false,
      'swagger-parser': false,
      'js-yaml': false,
      openai: false,
      'gpt-4-tokenizer': false
    }
  }
};
```

### For esbuild

Add the following to your esbuild config:

```javascript
esbuild.build({
  // ... your other esbuild options
  external: [
    'fs',
    'net',
    'tls',
    'child_process',
    'whois-json',
    'puppeteer',
    'node-port-scanner',
    'swagger-parser',
    'js-yaml',
    'openai',
    'gpt-4-tokenizer'
  ]
});
```

## Using with a Server-Side Proxy

For full functionality, consider setting up a server-side proxy that uses the full secure-web-scanner package. Your frontend can then call this API.

Example server endpoint:

```javascript
// Server (Express.js example)
const express = require('express');
const { scan } = require('secure-web-scanner');

const app = express();

app.get('/api/scan', async (req, res) => {
  const url = req.query.url;
  try {
    const results = await scan(url);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

This approach gives you full access to all secure-web-scanner features while keeping Node.js-specific code on the server.
