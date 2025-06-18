# secure-web-scanner v1.0.0

A comprehensive command-line tool to scan websites for security information, vulnerabilities, and technology stack details, now enhanced with AI-powered analysis, cloud security scanning, API security testing, authentication analysis, and interactive dashboards.

## Features

### Core Features
- 🔒 **SSL/TLS Information**: Check certificate validity, expiration dates, and issues
- 🔍 **HTTP Headers Analysis**: Analyze security headers and identify missing protections
- 🧰 **Advanced Tech Stack Detection**: Identify and analyze web servers, frameworks, CMS, JavaScript libraries with version detection and vulnerability scanning
- 📋 **WHOIS Information**: Get domain registration details
- 📊 **Security Assessment**: Get an overall security rating and recommendations

### Network Security Module
- 🚩 **Port Scanning with Fingerprinting**: Detect open ports, identify running services, and assess security implications
- 🔌 **Service Detection**: Identify services running on open ports 
- 🧪 **Custom Port Lists**: Scan specific ports or predefined groups

### Web Security Module
- 🛡️ **Enhanced CSP Analysis**: Deep analysis of Content Security Policy headers with directive-specific recommendations
- 🖥️ **Browser-based Analysis**: Advanced scanning using Puppeteer browser automation for deeper insights
- 🔎 **Form Security Analysis**: Check forms for CSRF tokens and secure submission methods
- 🔗 **Link Analysis**: Discover insecure links and analyze external dependencies

### CMS Scanning Module
- 🔍 **CMS Detection**: Identify popular content management systems (WordPress, Joomla, Drupal, etc.)
- 🛡️ **CMS Vulnerability Scanning**: Check for common security issues in detected CMS
- 📊 **Version Detection**: Identify CMS versions for vulnerability correlation

### Reconnaissance Module
- 🌐 **DNS Security Checks**: Analyze DNS records for security best practices (SPF, DMARC)
- 🔎 **Certificate Transparency**: Check certificate transparency logs for subdomain enumeration
- 🌍 **IP & ASN Information**: Get network intelligence on targets
- 🧰 **OSINT Integration**: Gather open-source intelligence on targets

### Additional Features
- 🍪 **Cookie Security**: Check cookies for secure flags and best practices
- 🎯 **Service Fingerprinting**: Identify software versions running on open ports
- 🔥 **Comprehensive Reports**: Get detailed security insights across multiple categories
- 📸 **Screenshot Capture**: Capture screenshots of target websites for visual inspection
- 🔬 **Client-side Vulnerability Detection**: Identify DOM-based XSS and other client-side security issues

### New Advanced Features

#### AI Module
- 🧠 **AI-Powered Analysis**: Use advanced language models to detect security vulnerabilities
- 🔍 **Pattern Recognition**: Identify complex security patterns beyond simple signature matching
- 💡 **Intelligent Recommendations**: Get context-aware security advice tailored to your environment

#### API Security Module
- 📡 **API Endpoint Discovery**: Automatically discover API endpoints in web applications
- 📝 **OpenAPI/Swagger Analysis**: Parse and analyze API specifications for security issues
- 🧪 **Active API Testing**: Test endpoints for common vulnerabilities like BOLA, injection, etc.

#### Authentication Security Module
- 🔑 **Login Form Analysis**: Assess security of authentication mechanisms
- 🔒 **Password Policy Checking**: Evaluate password requirements and implementation
- 🔄 **Session Management Analysis**: Review token security and session handling

#### Cloud Security Module
- ☁️ **Infrastructure Scanning**: Identify misconfigurations in cloud infrastructure
- 📄 **IaC Analysis**: Scan Terraform, CloudFormation, and other IaC templates
- 🔎 **Configuration Review**: Evaluate cloud service configurations for security best practices

#### Supply Chain Security Module
- 📦 **Dependency Scanning**: Check libraries and packages for known vulnerabilities
- 📈 **Version Analysis**: Identify outdated dependencies requiring updates
- 📝 **License Compliance**: Review dependency licenses for compliance issues

#### Enhanced Reporting & Dashboard
- 📊 **Interactive Dashboard**: Real-time monitoring of security scan results
- 📱 **Multiple Formats**: Generate reports in JSON, HTML, and PDF formats
- 📈 **Visual Analytics**: Visualize security findings with graphs and charts

See [ADVANCED_FEATURES.md](ADVANCED_FEATURES.md) for detailed documentation on all new capabilities.

## Installation

### Global Installation

```
npm install -g secure-web-scanner
```

### Local Installation

```
npm install secure-web-scanner
```

## Usage

### Basic Usage

```bash
# Install the package
npm install -g secure-web-scanner

# Run a basic scan
secure-web-scanner scan example.com

# Quick scan (no port scanning or DNS checks)
secure-web-scanner scan example.com --no-dns --no-ports

# Run a comprehensive scan with all advanced features
secure-web-scanner scan example.com --advanced --ai-scan --api-scan --auth-scan --cloud-scan --deps-scan
```

### Core Scanning Options

```bash
# Full scan with all core options
secure-web-scanner scan example.com --whois --dns --ports --port-level comprehensive

# Port scanning with specific ports
secure-web-scanner scan example.com --ports --port-list 22,80,443,3306

# Save results to file with multiple report formats
secure-web-scanner scan example.com --output results.json --report-format json,html,pdf

# Focus on technology stack and vulnerabilities
secure-web-scanner scan example.com --advanced-tech --vulnerabilities

# Run with interactive dashboard
secure-web-scanner scan example.com --interactive-dashboard --dashboard-port 3000
```

### Module-Specific Commands

```bash
# Subdomain discovery
secure-web-scanner subdomains example.com

# CMS detection and vulnerability scanning
secure-web-scanner cms example.com

# AI-powered vulnerability scanning
secure-web-scanner ai-scan example.com

# API security scanning
secure-web-scanner api https://api.example.com
secure-web-scanner api ./swagger.json --spec --base-url https://api.example.com

# Authentication security analysis
secure-web-scanner auth https://example.com/login

# Cloud configuration scanning
secure-web-scanner cloud ./terraform-files --provider aws

# Dependency security scanning
secure-web-scanner deps ./project-directory

# Report generation from existing scan results
secure-web-scanner report ./scan-results.json --format html --interactive
secure-web-scanner recon example.com --emails --social

# Web application security scanning
secure-web-scanner web https://example.com --forms --links --content
```

### Specialized Scans

```bash
# Subdomain discovery and validation
secure-web-scanner subdomains example.com -o subdomains.json

# Advanced web scan with Puppeteer
secure-web-scanner web example.com --puppeteer --screenshot
```

### Advanced Module Commands

```bash
# AI-powered vulnerability scanning
secure-web-scanner ai-scan /path/to/code --max-files 10

# API security scanning
secure-web-scanner api swagger.yaml --spec

# Cloud security scanning
secure-web-scanner cloud /path/to/terraform/files

# Supply chain security
secure-web-scanner deps /path/to/project

# Authentication security
secure-web-scanner auth https://example.com/login

# Interactive dashboard and enhanced reporting
secure-web-scanner scan example.com --interactive-dashboard --report-formats html,json
secure-web-scanner report scan-results.json --interactive
```

### Using Convenience Scripts

For a full-featured scan with all enhanced modules enabled, use the provided convenience scripts:

```bash
# On Linux/macOS
./comprehensive-scan.sh example.com

# On Windows (PowerShell)
.\comprehensive-scan.ps1 example.com
```

## CLI Options

### Basic Options

| Option | Description |
|--------|-------------|
| `<target>` | URL or domain to scan |
| `-o, --output <path>` | Save results to a JSON file |
| `-f, --format <format>` | Output format (table, json) |
| `-a, --advanced` | Run all available checks including advanced ones |

### Scan Selection Options

| Option | Description |
|--------|-------------|
| `-s, --no-ssl` | Skip SSL check |
| `-h, --no-headers` | Skip headers check |
| `-t, --no-tech` | Skip technology detection |
| `-w, --whois` | Include WHOIS lookup |
| `-d, --dns` | Include DNS security checks |
| `-p, --ports` | Include port scanning |
| `-c, --no-cookies` | Skip cookie security checks |
| `-g, --no-csp` | Skip Content Security Policy checks |
| `--subdomain` | Enable subdomain discovery and analysis |
| `--advanced-tech` | Enable deep technology detection with version identification |
| `-v, --vulnerabilities` | Focus on finding security vulnerabilities in the tech stack |

### Advanced Configuration Options

| Option | Description |
|--------|-------------|
| `--port-list <ports>` | Comma-separated list of ports to scan |
| `--port-level <level>` | Port scan level (minimal, web, standard, comprehensive) |
| `--fingerprint` | Enable service fingerprinting on open ports |
| `--max-subdomains <number>` | Maximum number of subdomains to check (default 30) |

### External Subdomain Finder Options

| Option | Description |
|--------|-------------|
| `--max-resolve <number>` | Maximum number of subdomains to resolve IPs for (default: 20) |
| `--format <format>` | Output format: table or json (default: table) |

## Scan Features in Detail

### SSL/TLS Analysis
- Certificate validation
- Expiration check
- Protocol support
- Cipher strengths
- Common vulnerabilities

### Security Headers
- CSP analysis
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Strict-Transport-Security
- Referrer-Policy
- Feature-Policy/Permissions-Policy
- Recommendations for missing headers

### Content Security Policy (CSP) Analysis
- Directive presence and strength
- Detection of unsafe directives (`unsafe-inline`, `unsafe-eval`)
- Wildcard checks
- Nonce and hash implementation detection
- Reporting configuration
- Directive-specific recommendations

### Port Scanning
- Multiple scan levels
- Service fingerprinting
- Banner grabbing
- Security recommendations by port and service
- Critical service detection

### Subdomain Discovery
- Enumeration of common subdomains
- HTTP/HTTPS availability checks
- Insecure protocol detection
- Information leakage analysis
- Administrative interface detection
- Development environment discovery

### Technology Stack Analysis
- Web server detection with versions
- Framework identification
- CMS detection
- JavaScript libraries with versions
- Plugin enumeration
- Version-based vulnerability checking
- Common misconfigurations

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
