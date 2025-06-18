## Browser-Based Analysis Features

secure-web-scanner now integrates Puppeteer to enable advanced browser-based analysis capabilities. These features provide deeper insights into client-side security that traditional scanner tools miss.

### Puppeteer-Powered Features

- **Client-Side Vulnerability Detection**
  - Identify DOM-based XSS vulnerabilities
  - Detect unsafe JavaScript practices
  - Find insecure form submissions
  - Identify mixed content issues

- **Visual Analysis**
  - Capture full page screenshots for visual inspection
  - Document the visual state of websites

- **Content Security Analysis**
  - Deep inspection of iframes and sandbox attribute usage
  - Analyze third-party resource loading
  - Identify insecure content inclusion patterns
  - Track all resources loaded by the page

- **Link Discovery & Analysis**
  - Extract all links from rendered pages (including dynamically generated links)
  - Identify same-domain vs external links
  - Detect potentially dangerous URLs

- **Interactive Testing**
  - Automated form interaction
  - Test login functionality (with provided credentials)
  - Analyze session management

- **Storage & Cookie Analysis**
  - Detect sensitive information in localStorage/sessionStorage
  - Identify JWT tokens stored in insecure locations
  - Find security issues in cookie implementation

### Enabling Browser-Based Scanning

To use the Puppeteer-powered features, use one of these flags:

```bash
# Enable all Puppeteer-based scanning features
secure-web-scanner example.com --puppeteer

# Enable specific Puppeteer features
secure-web-scanner example.com --screenshot --client-side-vulns --content-security
```

For interactive scanning that involves login attempts:

```bash
# This would be implemented with a future feature that accepts credentials
secure-web-scanner example.com --interactive-scan --credentials-file creds.json
```
