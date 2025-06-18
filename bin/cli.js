#!/usr/bin/env node
const { 
  scan, 
  findLiveSubdomains, 
  formatSubdomainResults, 
  enhancedPortScan, 
  detectCMS, 
  scanCMSVulnerabilities, 
  performRecon, 
  scanWeb, 
  scanApi, 
  detectVulnerabilities, 
  scanCloud, 
  scanDependencies,
  generateReport,
  serveDashboard,
  analyzeAuthForm
} = require('../lib/index');
const chalk = require('chalk');
const ora = require('ora');
const { program } = require('commander');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

// Get version from package.json
const packageJson = require('../package.json');
const version = packageJson.version;

program
  .version(version)
  .name('secure-web-scanner')
  .description('A tool to scan websites for security information and technology stack details');

// Add API security command
program
  .command('api <target>')
  .description('Scan API endpoints or analyze API specifications for security vulnerabilities')
  .option('-s, --spec', 'Target is an API specification file (OpenAPI/Swagger)')
  .option('-b, --base-url <url>', 'Base URL for active API testing')
  .option('-a, --active-testing', 'Perform active testing of API endpoints')
  .option('-d, --discover', 'Discover API endpoints by crawling the website')
  .option('-o, --output <path>', 'Path to save the results')
  .option('-f, --format <format>', 'Output format (json, html)', 'json')
  .action(async (target, options) => {
    console.log(chalk.blue('🔍 API Security Scanner'));
    console.log(chalk.gray(`Target: ${target}`));
    
    const spinner = ora('Scanning API...').start();
    try {
      // Configure scan options
      const scanOptions = {
        baseUrl: options.baseUrl,
        activeTesting: options.activeTesting,
        discover: options.discover
      };
      
      // Run API security scan
      const results = await scanApi(target, scanOptions);
      spinner.succeed('API security scan completed');
      
      // Generate report if output specified
      if (options.output) {
        const outputPath = path.resolve(options.output);
        const reportOptions = {
          formats: [options.format],
          outputPath
        };
        
        const reportResult = await generateReport(results, reportOptions);
        console.log(chalk.green(`Report saved to ${reportResult.reports[0].path}`));
      } else {
        console.log(JSON.stringify(results, null, 2));
      }
    } catch (error) {
      spinner.fail(`API scan failed: ${error.message}`);
      if (error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

// Add AI-powered vulnerability detection command
program
  .command('ai-scan <target>')
  .description('Use AI to detect vulnerabilities in source code or web applications')
  .option('-e, --extensions <exts>', 'Comma-separated file extensions to scan', '.js,.ts,.jsx,.tsx,.py,.php')
  .option('--no-pattern', 'Disable pattern-based detection')
  .option('--no-ai', 'Disable AI-based detection')
  .option('-m, --max-files <count>', 'Maximum number of files to analyze with AI', '5')
  .option('-o, --output <path>', 'Path to save the results')
  .option('-f, --format <format>', 'Output format (json, html)', 'json')
  .action(async (target, options) => {
    console.log(chalk.blue('🧠 AI-Powered Vulnerability Scanner'));
    console.log(chalk.gray(`Target: ${target}`));
    
    const spinner = ora('Scanning for vulnerabilities...').start();
    try {
      // Parse extensions
      const extensions = options.extensions.split(',');
      
      // Configure scan options
      const scanOptions = {
        useAI: options.ai,
        usePatterns: options.pattern,
        extensions,
        maxAIFiles: parseInt(options.maxFiles, 10)
      };
      
      // Run vulnerability detection
      const results = await detectVulnerabilities(target, scanOptions);
      spinner.succeed('Vulnerability scan completed');
      
      // Generate report if output specified
      if (options.output) {
        const outputPath = path.resolve(options.output);
        const reportOptions = {
          formats: [options.format],
          outputPath
        };
        
        const reportResult = await generateReport(results, reportOptions);
        console.log(chalk.green(`Report saved to ${reportResult.reports[0].path}`));
      } else {
        console.log(JSON.stringify(results, null, 2));
      }
    } catch (error) {
      spinner.fail(`AI scan failed: ${error.message}`);
      if (error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

// Add cloud security command
program
  .command('cloud <target>')
  .description('Scan cloud infrastructure or configuration files for security issues')
  .option('-p, --provider <n>', 'Cloud provider name (aws, azure, gcp)')
  .option('-c, --config-only', 'Only scan configuration files, no API calls')
  .option('-o, --output <path>', 'Path to save the results')
  .option('-f, --format <format>', 'Output format (json, html)', 'json')
  .action(async (target, options) => {
    console.log(chalk.blue('☁️ Cloud Security Scanner'));
    console.log(chalk.gray(`Target: ${target}`));
    
    const spinner = ora('Scanning cloud resources...').start();
    try {
      // Configure scan options
      const scanOptions = {
        provider: options.provider,
        configOnly: options.configOnly
      };
      
      // Run cloud security scan
      const results = await scanCloud(target, scanOptions);
      spinner.succeed('Cloud security scan completed');
      
      // Generate report if output specified
      if (options.output) {
        const outputPath = path.resolve(options.output);
        const reportOptions = {
          formats: [options.format],
          outputPath
        };
        
        const reportResult = await generateReport(results, reportOptions);
        console.log(chalk.green(`Report saved to ${reportResult.reports[0].path}`));
      } else {
        console.log(JSON.stringify(results, null, 2));
      }
    } catch (error) {
      spinner.fail(`Cloud scan failed: ${error.message}`);
      if (error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

// Add supply chain security command
program
  .command('deps <target>')
  .description('Scan project dependencies for security vulnerabilities')
  .option('-n, --no-npm', 'Skip npm package scanning')
  .option('-p, --no-python', 'Skip Python package scanning')
  .option('-l, --no-licenses', 'Skip license checking')
  .option('-o, --output <path>', 'Path to save the results')
  .option('-f, --format <format>', 'Output format (json, html)', 'json')
  .action(async (target, options) => {
    console.log(chalk.blue('📦 Dependency Security Scanner'));
    console.log(chalk.gray(`Target: ${target}`));
    
    const spinner = ora('Scanning dependencies...').start();
    try {
      // Configure scan options
      const scanOptions = {
        checkNpm: options.npm,
        checkPython: options.python,
        checkLicenses: options.licenses
      };
      
      // Run dependency security scan
      const results = await scanDependencies(target, scanOptions);
      spinner.succeed('Dependency security scan completed');
      
      // Generate report if output specified
      if (options.output) {
        const outputPath = path.resolve(options.output);
        const reportOptions = {
          formats: [options.format],
          outputPath
        };
        
        const reportResult = await generateReport(results, reportOptions);
        console.log(chalk.green(`Report saved to ${reportResult.reports[0].path}`));
      } else {
        console.log(JSON.stringify(results, null, 2));
      }
    } catch (error) {
      spinner.fail(`Dependency scan failed: ${error.message}`);
      if (error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

// Add auth security command
program
  .command('auth <login-url>')
  .description('Analyze authentication security on a login page')
  .option('-o, --output <path>', 'Path to save the results')
  .option('-f, --format <format>', 'Output format (json, html)', 'json')
  .action(async (loginUrl, options) => {
    console.log(chalk.blue('🔑 Authentication Security Scanner'));
    console.log(chalk.gray(`Target: ${loginUrl}`));
    
    const spinner = ora('Analyzing authentication...').start();
    try {
      // Run authentication security analysis
      const results = await analyzeAuthForm(loginUrl);
      spinner.succeed('Authentication security analysis completed');
      
      // Generate report if output specified
      if (options.output) {
        const outputPath = path.resolve(options.output);
        const reportOptions = {
          formats: [options.format],
          outputPath
        };
        
        const reportResult = await generateReport(results, reportOptions);
        console.log(chalk.green(`Report saved to ${reportResult.reports[0].path}`));
      } else {
        console.log(JSON.stringify(results, null, 2));
      }
    } catch (error) {
      spinner.fail(`Authentication analysis failed: ${error.message}`);
      if (error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

// Add report generation command
program
  .command('report <input-file>')
  .description('Generate reports from scan results')
  .option('-o, --output <path>', 'Path to save the report')
  .option('-f, --format <format>', 'Report format (json, html, pdf)', 'html')
  .option('-i, --interactive', 'Start an interactive dashboard')
  .option('-p, --port <port>', 'Port for interactive dashboard', '3000')
  .action(async (inputFile, options) => {
    console.log(chalk.blue('📊 Report Generator'));
    
    try {
      // Load scan results
      const fs = require('fs');
      const scanResults = JSON.parse(fs.readFileSync(inputFile, 'utf-8'));
      
      // Configure report options
      const reportOptions = {
        formats: [options.format],
        outputPath: options.output || `./report-${Date.now()}.${options.format}`,
        interactive: options.interactive,
        port: parseInt(options.port, 10)
      };
      
      // Generate report
      const result = await generateReport(scanResults, reportOptions);
      
      if (result.reports && result.reports.length > 0) {
        console.log(chalk.green(`Report generated at: ${result.reports[0].path}`));
      }
      
      if (options.interactive) {
        console.log(chalk.green(`Interactive dashboard available at: ${result.dashboard.url}`));
        console.log(chalk.gray('Press Ctrl+C to stop the dashboard server.'));
        
        // Keep process running for dashboard
        process.stdin.resume();
      }
    } catch (error) {
      console.error(chalk.red(`Report generation failed: ${error.message}`));
      if (error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

// New subdomain enumeration command
program
  .command('subdomains <domain>')
  .description('Discover and validate live subdomains for a given domain')
  .option('-o, --output <path>', 'Save results to a JSON file')
  .option('-f, --format <format>', 'Output format (text, json)', 'text')
  .action(async (domain, options) => {
    console.log(chalk.blue('🔍 Subdomain Enumeration', chalk.gray(`v${version}`)));
    console.log(chalk.gray(`Target: ${domain}`));
    
    try {
      // Run the subdomain scanner
      const results = await findLiveSubdomains(domain);
      
      // Format and display results
      if (options.format === 'json') {
        console.log(JSON.stringify(results, null, 2));
      } else {
        console.log(formatSubdomainResults(results, domain));
      }

      // Save to file if output path provided
      if (options.output) {
        const outputPath = path.resolve(options.output);
        await fs.promises.writeFile(outputPath, 
          options.format === 'json' 
            ? JSON.stringify(results, null, 2) 
            : formatSubdomainResults(results, domain)
        );
        console.log(chalk.green(`\nResults saved to ${outputPath}`));
      }
    } catch (error) {
      console.error(chalk.red(`Subdomain scan failed: ${error.message}`));
      if (error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

// Default command (original scan functionality)
program.command('scan <target>', { isDefault: true })
  .description('Perform comprehensive security scan on a target website')
  .option('-o, --output <path>', 'Save results to a JSON file')
  .option('-s, --no-ssl', 'Skip SSL check')
  .option('-h, --no-headers', 'Skip headers check')
  .option('-t, --no-tech', 'Skip technology detection')
  .option('-w, --whois', 'Include WHOIS lookup')
  .option('-d, --dns', 'Include DNS security checks')
  .option('-p, --ports', 'Include port scanning')
  .option('-c, --no-cookies', 'Skip cookie security checks')
  .option('-g, --no-csp', 'Skip Content Security Policy checks')
  .option('--port-list <ports>', 'Comma-separated list of ports to scan')
  .option('--port-level <level>', 'Port scan level (minimal, web, standard, comprehensive)', 'minimal')
  .option('--fingerprint', 'Enable service fingerprinting on open ports')
  .option('-a, --advanced', 'Run all available checks including advanced ones')
  .option('--advanced-tech', 'Enable deep technology detection with version identification')
  .option('-v, --vulnerabilities', 'Focus on finding security vulnerabilities in the tech stack')
  .option('-f, --format <format>', 'Output format (table, json, html, pdf)', 'table')
  // Puppeteer-based options
  .option('--puppeteer', 'Enable advanced scanning with Puppeteer')
  .option('--screenshot', 'Take screenshot of the target website')
  .option('--screenshot-path <path>', 'Path to save the screenshot')
  .option('--client-side-vulns', 'Scan for client-side vulnerabilities')
  .option('--extract-links', 'Extract all links from the page')
  .option('--interactive-scan', 'Perform interactive scanning (e.g., form submission)')
  .option('--content-security', 'Analyze content security (iframes, 3rd-party resources)')
  .option('--save-artifacts', 'Save scan artifacts (screenshots, DOM dumps, etc.)')
  // New advanced options
  .option('--ai-scan', 'Enable AI-powered vulnerability detection')
  .option('--api-scan', 'Discover and analyze APIs')
  .option('--auth-scan', 'Analyze authentication security')
  .option('--cloud-scan', 'Scan for cloud infrastructure misconfigurations')
  .option('--deps-scan', 'Analyze dependencies for vulnerabilities')
  .option('-i, --interactive-dashboard', 'Launch an interactive dashboard when scan completes')
  .option('--dashboard-port <port>', 'Port for interactive dashboard', '3000')
  .option('--report-format <formats>', 'Comma-separated list of report formats (json,html,pdf)', 'json')
  .action(async (target, options) => {
    console.log(chalk.blue('🔍 Web Security Scanner', chalk.gray(`v${version}`)));
    console.log(chalk.gray(`Target: ${target}`));
    
    const spinner = ora('Scanning...').start();
    try {
      // Create a unique scan ID for this scan
      const scanId = uuidv4();
      console.log(chalk.gray(`Scan ID: ${scanId}`));
      
      // Parse port list if provided
      let ports = null;
      if (options.portList) {
        ports = options.portList.split(',').map(p => parseInt(p.trim(), 10));
      }
      
      // Parse report formats if provided
      let reportFormats = ['json'];
      if (options.reportFormat) {
        reportFormats = options.reportFormat.split(',').map(f => f.trim().toLowerCase());
      }
      
      // Set advanced options based on flags
      const scanOptions = {
        scanId: scanId, // Unique scan ID for tracking and reporting
        checkSSL: options.ssl,
        checkHeaders: options.headers,
        detectTech: options.tech,
        getWhois: options.whois || options.advanced,
        checkDns: options.dns || options.advanced,
        scanPorts: options.ports || options.advanced,
        checkCookies: options.cookies,
        checkCSP: options.csp,
        advancedTechDetection: options.advancedTech === true || options.advanced || options.vulnerabilities,
        focusOnVulnerabilities: options.vulnerabilities === true,
        portScanLevel: options.portLevel || 'minimal',
        fingerprint: options.fingerprint === true || options.advanced,
        ports: ports,
        // Puppeteer options
        usePuppeteer: options.puppeteer || options.screenshot || 
                      options.clientSideVulns || options.extractLinks || 
                      options.contentSecurity || options.authScan,
        puppeteerOptions: {
          takeScreenshot: options.screenshot === true,
          screenshotPath: options.screenshotPath || null,
          scanClientSideVulns: options.clientSideVulns === true || options.puppeteer === true,
          extractLinks: options.extractLinks === true || options.puppeteer === true,
          interactiveScan: options.interactiveScan === true,
          contentSecurityAnalysis: options.contentSecurity === true || options.puppeteer === true,
          saveArtifacts: options.saveArtifacts === true
        },
        // New advanced options
        useAI: options.aiScan === true || options.advanced === true,
        apiScan: options.apiScan === true || options.advanced === true,
        authScan: options.authScan === true || options.advanced === true,
        cloudScan: options.cloudScan === true || options.advanced === true,
        depsScan: options.depsScan === true || options.advanced === true,
        interactiveDashboard: options.interactiveDashboard === true,
        dashboardPort: options.dashboardPort ? parseInt(options.dashboardPort, 10) : 3000,
        reportFormats: reportFormats,
        timeout: 30000
      };
      
      // Run the scan
      const results = await scan(target, scanOptions);
      
      spinner.succeed('Scan completed');
      
    // Display results based on format
      if (options.format === 'json') {
        console.log(JSON.stringify(results, null, 2));
      } else {
        // Add a header separator for better visual appearance
        console.log(chalk.gray('─'.repeat(process.stdout.columns || 80)));
        displayTableResults(results);
        console.log(chalk.gray('─'.repeat(process.stdout.columns || 80)));
      }
      
      // Generate reports based on specified formats
      if (options.output) {
        const outputPath = path.resolve(options.output);
        const baseOutputPath = outputPath.replace(/\.\w+$/, ''); // Remove extension if present
        
        // Configure report options
        const reportOptions = {
          formats: reportFormats,
          outputPath: baseOutputPath,
          interactive: options.interactiveDashboard === true,
          port: options.dashboardPort ? parseInt(options.dashboardPort, 10) : 3000
        };
        
        const reportResult = await generateReport(results, reportOptions);
        
        // Log information about generated reports
        if (reportResult.reports && reportResult.reports.length > 0) {
          reportResult.reports.forEach(report => {
            console.log(chalk.green(`\nReport saved to: ${report.path}`));
          });
        }
        
        // Start interactive dashboard if requested
        if (options.interactiveDashboard && reportResult.dashboard) {
          console.log(chalk.green(`\nInteractive dashboard available at: ${reportResult.dashboard.url}`));
          console.log(chalk.gray('Press Ctrl+C to stop the dashboard server.'));
          
          // Keep process running for dashboard
          process.stdin.resume();
        }
      }
    } catch (error) {
      spinner.fail('Scan failed');
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

// New command: CMS detection and scanning
program
  .command('cms <target>')
  .description('Detect CMS and scan for vulnerabilities')
  .option('-o, --output <path>', 'Save results to a JSON file')
  .option('-f, --format <format>', 'Output format (text, json)', 'text')
  .action(async (target, options) => {
    console.log(chalk.blue('🔍 CMS Detection and Scanning', chalk.gray(`v${version}`)));
    console.log(chalk.gray(`Target: ${target}`));
    
    const spinner = ora('Detecting CMS...').start();
    try {
      // Detect CMS
      const cmsDetectionResults = await detectCMS(target);
      spinner.succeed('CMS detection completed');
      
      // Display CMS detection results
      if (options.format === 'json') {
        console.log(JSON.stringify(cmsDetectionResults, null, 2));
      } else {
        console.log(formatCMSResults(cmsDetectionResults));
      }
      
      // Save to file if output path provided
      if (options.output) {
        const outputPath = path.resolve(options.output);
        await fs.promises.writeFile(outputPath, 
          options.format === 'json' 
            ? JSON.stringify(cmsDetectionResults, null, 2) 
            : formatCMSResults(cmsDetectionResults)
        );
        console.log(chalk.green(`\nCMS detection results saved to ${outputPath}`));
      }
      
      // If CMS detected, scan for vulnerabilities
      if (cmsDetectionResults.cms && cmsDetectionResults.cms.name) {
        console.log(chalk.blue(`Scanning for vulnerabilities in ${cmsDetectionResults.cms.name}...`));
        const vulnSpinner = ora('Scanning for vulnerabilities...').start();
        try {
          const vulnResults = await scanCMSVulnerabilities(target, cmsDetectionResults.cms.name);
          vulnSpinner.succeed('Vulnerability scanning completed');
          
          // Display vulnerability scan results
          if (options.format === 'json') {
            console.log(JSON.stringify(vulnResults, null, 2));
          } else {
            console.log(formatVulnResults(vulnResults));
          }
          
          // Save to file if output path provided
          if (options.output) {
            const outputPath = path.resolve(options.output);
            await fs.promises.writeFile(outputPath, 
              options.format === 'json' 
                ? JSON.stringify(vulnResults, null, 2) 
                : formatVulnResults(vulnResults)
            );
            console.log(chalk.green(`\nVulnerability scan results saved to ${outputPath}`));
          }
        } catch (vulnError) {
          vulnSpinner.fail('Vulnerability scan failed');
          console.error(chalk.red(`Vulnerability scan error: ${vulnError.message}`));
        }
      }
    } catch (error) {
      spinner.fail('CMS detection failed');
      console.error(chalk.red(`Error: ${error.message}`));
      process.exit(1);
    }
  });

// Network scanning command
program
  .command('network <target>')
  .description('Perform network scanning with port detection and service fingerprinting')
  .option('-o, --output <path>', 'Save results to a JSON file')
  .option('-p, --port-level <level>', 'Port scan level (minimal, web, standard, comprehensive)', 'standard')
  .option('--port-list <ports>', 'Comma-separated list of ports to scan')
  .option('-f, --fingerprint', 'Enable service fingerprinting on open ports', true)
  .option('--timeout <ms>', 'Timeout in milliseconds', '10000')
  .option('--filter', 'Filter results to show only open ports', true)
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (target, options) => {
    console.log(chalk.blue('🔍 Network Scanner', chalk.gray(`v${version}`)));
    console.log(chalk.gray(`Target: ${target}`));
    
    const spinner = ora('Scanning network...').start();
    try {
      // Parse custom ports if provided
      let customPorts = null;
      if (options.portList) {
        customPorts = options.portList.split(',').map(p => parseInt(p.trim(), 10));
      }
      
      // Run the enhanced port scan
      const results = await enhancedPortScan(target, {
        portLevel: options.portLevel,
        customPorts: customPorts,
        timeout: parseInt(options.timeout, 10),
        fingerprint: options.fingerprint,
        filterClosed: options.filter
      });
      
      spinner.succeed('Network scan completed');
      
      // Display results
      if (options.format === 'json') {
        console.log(JSON.stringify(results, null, 2));
      } else {
        console.log('\n' + chalk.blue('📊 Open Ports'));
        if (results.ports.length === 0) {
          console.log(chalk.yellow('  No open ports found'));
        } else {
          console.log(chalk.gray('  PORT     STATE    SERVICE'));
          results.ports.forEach(port => {
            console.log(`  ${port.port.toString().padEnd(8)} ${
              port.open ? chalk.green('open') : chalk.red('closed')
            }    ${port.service?.service || 'unknown'} ${
              port.service?.product ? chalk.gray(`(${port.service.product})`) : ''
            }`);
          });
          
          // Show security analysis
          if (results.analysis && results.analysis.findings) {
            console.log('\n' + chalk.blue('📝 Security Findings'));
            results.analysis.findings.forEach(finding => {
              console.log(`  ${chalk.yellow('•')} ${finding}`);
            });
          }
        }
      }
      
      // Save to file if output path provided
      if (options.output) {
        const outputPath = path.resolve(options.output);
        await fs.promises.writeFile(outputPath, JSON.stringify(results, null, 2));
        console.log(chalk.green(`\nResults saved to ${outputPath}`));
      }
      
    } catch (error) {
      spinner.fail('Network scan failed');
      console.error(chalk.red(`Error: ${error.message}`));
      if (error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

// Recon command
program
  .command('recon <target>')
  .description('Perform reconnaissance on a domain or IP')
  .option('-o, --output <path>', 'Save results to a JSON file')
  .option('--no-whois', 'Skip WHOIS lookup')
  .option('--no-dns', 'Skip DNS enumeration')
  .option('--no-cert', 'Skip certificate transparency checks')
  .option('--no-asn', 'Skip ASN lookup')
  .option('--emails', 'Include email harvesting')
  .option('--social', 'Check for social media presence')
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (target, options) => {
    console.log(chalk.blue('🔍 Reconnaissance', chalk.gray(`v${version}`)));
    console.log(chalk.gray(`Target: ${target}`));
    
    const spinner = ora('Gathering intelligence...').start();
    try {
      // Set up options for recon
      const reconOptions = {
        whois: options.whois,
        dns: options.dns,
        certificates: options.cert,
        asn: options.asn,
        emails: options.emails,
        social: options.social
      };
      
      // Run the recon
      const results = await performRecon(target, reconOptions);
      spinner.succeed('Reconnaissance completed');
      
      // Display results
      if (options.format === 'json') {
        console.log(JSON.stringify(results, null, 2));
      } else {
        console.log('\n' + chalk.blue('📊 Reconnaissance Results'));
        console.log(`  ${chalk.gray('Target:')} ${target} (${results.targetType})`);
        
        // Show IP information if available
        if (results.ip && !results.ip.error) {
          console.log(`\n  ${chalk.yellow('IP Information:')}`);
          if (results.targetType === 'domain') {
            if (results.ip.ipv4 && results.ip.ipv4.length > 0) {
              console.log(`    ${chalk.gray('IPv4:')} ${results.ip.ipv4.join(', ')}`);
            }
            if (results.ip.ipv6 && results.ip.ipv6.length > 0) {
              console.log(`    ${chalk.gray('IPv6:')} ${results.ip.ipv6.join(', ')}`);
            }
          }
        }
        
        // Show WHOIS information if available
        if (results.whois && !results.whois.error && results.whois.parsed) {
          console.log(`\n  ${chalk.yellow('WHOIS Information:')}`);
          const whois = results.whois.parsed;
          if (whois.registrar) console.log(`    ${chalk.gray('Registrar:')} ${whois.registrar}`);
          if (whois.creationDate) console.log(`    ${chalk.gray('Created:')} ${new Date(whois.creationDate).toLocaleDateString()}`);
          if (whois.expirationDate) console.log(`    ${chalk.gray('Expires:')} ${new Date(whois.expirationDate).toLocaleDateString()}`);
          if (whois.nameServers) console.log(`    ${chalk.gray('Name Servers:')} ${whois.nameServers.join(', ')}`);
        }
        
        // Show ASN information if available
        if (results.asn && !results.asn.error) {
          console.log(`\n  ${chalk.yellow('ASN Information:')}`);
          if (results.asn.asn) console.log(`    ${chalk.gray('ASN:')} ${results.asn.asn}`);
          if (results.asn.organization) console.log(`    ${chalk.gray('Organization:')} ${results.asn.organization}`);
          if (results.asn.country) console.log(`    ${chalk.gray('Country:')} ${results.asn.country}`);
        }
        
        // Show certificate information if available
        if (results.certificates && !results.certificates.error) {
          console.log(`\n  ${chalk.yellow('Certificate Transparency:')}`);
          if (results.certificates.found) {
            console.log(`    ${chalk.gray('Certificates Found:')} ${results.certificates.count}`);
            if (results.certificates.certificates && results.certificates.certificates.length > 0) {
              console.log(`    ${chalk.gray('Recent Certificates:')}`);
              results.certificates.certificates.slice(0, 3).forEach(cert => {
                console.log(`      - Issued by: ${cert.issuer.split(',')[0].replace('CN=', '')}`);
                console.log(`        Subject: ${cert.subject}`);
                console.log(`        Valid: ${new Date(cert.validFrom).toLocaleDateString()} to ${new Date(cert.validTo).toLocaleDateString()}`);
              });
              if (results.certificates.certificates.length > 3) {
                console.log(`        ${chalk.gray('... and')} ${results.certificates.certificates.length - 3} ${chalk.gray('more')}`);
              }
            }
          } else {
            console.log(`    ${chalk.gray('No certificates found in transparency logs')}`);
          }
        }
      }
      
      // Save to file if output path provided
      if (options.output) {
        const outputPath = path.resolve(options.output);
        await fs.promises.writeFile(outputPath, JSON.stringify(results, null, 2));
        console.log(chalk.green(`\nResults saved to ${outputPath}`));
      }
      
    } catch (error) {
      spinner.fail('Reconnaissance failed');
      console.error(chalk.red(`Error: ${error.message}`));
      if (error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

// Web scanning command
program
  .command('web <url>')
  .description('Perform comprehensive web application security scan')
  .option('-o, --output <path>', 'Save results to a JSON file')
  .option('-s, --no-ssl', 'Skip SSL check')
  .option('-h, --no-headers', 'Skip headers check')
  .option('-c, --no-cookies', 'Skip cookie security checks')
  .option('-g, --no-csp', 'Skip Content Security Policy checks')
  .option('-f, --forms', 'Check form security')
  .option('-l, --links', 'Analyze links')
  .option('--content', 'Analyze content security')
  .option('--xss', 'Basic XSS detection')
  .option('--screenshot', 'Take screenshot of the target website')
  .option('--screenshot-path <path>', 'Path to save the screenshot')
  .option('--puppeteer', 'Use Puppeteer for advanced scanning')
  .option('--format <format>', 'Output format (table, json)', 'table')
  .action(async (url, options) => {
    console.log(chalk.blue('🔍 Web Security Scanner', chalk.gray(`v${version}`)));
    console.log(chalk.gray(`Target: ${url}`));
    
    const spinner = ora('Scanning website...').start();
    try {
      // Set up options for web scan
      const scanOptions = {
        ssl: options.ssl,
        headers: options.headers,
        csp: options.csp,
        cookies: options.cookies,
        formSecurity: options.forms,
        linkAnalysis: options.links,
        contentSecurity: options.content,
        screenshot: options.screenshot,
        screenshotPath: options.screenshotPath,
        xssDetection: options.xss,
        usePuppeteer: options.puppeteer || options.screenshot
      };
      
      // Run the web scan
      const results = await scanWeb(url, scanOptions);
      spinner.succeed('Web scan completed');
      
      // Display results
      if (options.format === 'json') {
        console.log(JSON.stringify(results, null, 2));
      } else {
        console.log('\n' + chalk.blue('📊 Web Security Results'));
        
        // Show overall score if available
        if (results.securityScore) {
          console.log(`  ${chalk.gray('Security Score:')} ${colorizeScore(results.securityScore.score)} ${chalk.gray(`(${results.securityScore.rating})`)}`);
        }
        
        // Show SSL results if available
        if (results.ssl && !results.ssl.error) {
          const sslAnalysis = results.ssl.analysis;
          console.log(`\n  ${chalk.yellow('SSL/TLS:')} ${colorizeScore(sslAnalysis.score, 25)} ${sslAnalysis.valid ? chalk.green('✓') : chalk.red('✗')}`);
          if (sslAnalysis.grade) console.log(`    ${chalk.gray('Grade:')} ${sslAnalysis.grade}`);
          if (sslAnalysis.issues && sslAnalysis.issues.length > 0) {
            console.log(`    ${chalk.gray('Issues:')}`);
            sslAnalysis.issues.forEach(issue => {
              console.log(`      - ${issue}`);
            });
          }
        }
        
        // Show header results if available
        if (results.headers && !results.headers.error) {
          const headerAnalysis = results.headers.analysis;
          console.log(`\n  ${chalk.yellow('Security Headers:')} ${colorizeScore(headerAnalysis.score, 25)}`);
          if (headerAnalysis.present && headerAnalysis.present.length > 0) {
            console.log(`    ${chalk.gray('Present:')}`);
            headerAnalysis.present.forEach(header => {
              console.log(`      - ${chalk.green(header)}`);
            });
          }
          if (headerAnalysis.missing && headerAnalysis.missing.length > 0) {
            console.log(`    ${chalk.gray('Missing:')}`);
            headerAnalysis.missing.forEach(header => {
              console.log(`      - ${chalk.red(header)}`);
            });
          }
        }
        
        // Show CSP results if available
        if (results.csp && results.csp.analysis) {
          const cspAnalysis = results.csp.analysis;
          console.log(`\n  ${chalk.yellow('Content Security Policy:')} ${cspAnalysis.implemented ? chalk.green('✓') : chalk.red('✗')}`);
          if (cspAnalysis.implemented) {
            console.log(`    ${chalk.gray('Score:')} ${colorizeScore(cspAnalysis.score, 15)}`);
            if (cspAnalysis.recommendations && cspAnalysis.recommendations.length > 0) {
              console.log(`    ${chalk.gray('Recommendations:')}`);
              cspAnalysis.recommendations.slice(0, 3).forEach(rec => {
                console.log(`      - ${rec}`);
              });
              if (cspAnalysis.recommendations.length > 3) {
                console.log(`        ${chalk.gray('... and')} ${cspAnalysis.recommendations.length - 3} ${chalk.gray('more')}`);
              }
            }
          } else {
            console.log(`    ${chalk.gray('Recommendation:')} Implement Content Security Policy`);
          }
        }
        
        // Show cookie results if available
        if (results.cookies && results.cookies.analysis) {
          const cookieAnalysis = results.cookies.analysis;
          console.log(`\n  ${chalk.yellow('Cookie Security:')} ${colorizeScore(cookieAnalysis.score, 15)}`);
          if (cookieAnalysis.issues && cookieAnalysis.issues.length > 0) {
            console.log(`    ${chalk.gray('Issues:')}`);
            cookieAnalysis.issues.forEach(issue => {
              console.log(`      - ${issue}`);
            });
          } else {
            console.log(`    ${chalk.green('✓')} No cookie security issues found`);
          }
        }
        
        // Show form results if available
        if (results.forms) {
          console.log(`\n  ${chalk.yellow('Form Security:')}`);
          console.log(`    ${chalk.gray('Forms Found:')} ${results.forms.count}`);
          if (results.forms.forms && results.forms.forms.length > 0) {
            const insecureForms = results.forms.forms.filter(form => form.securityIssues.length > 0);
            if (insecureForms.length > 0) {
              console.log(`    ${chalk.gray('Forms with Issues:')} ${insecureForms.length}`);
              insecureForms.forEach(form => {
                console.log(`      ${chalk.gray(form.id || 'Form')}:`);
                form.securityIssues.forEach(issue => {
                  console.log(`        - ${issue}`);
                });
              });
            } else {
              console.log(`    ${chalk.green('✓')} No form security issues found`);
            }
          }
        }
        
        // Show link analysis if available
        if (results.links) {
          console.log(`\n  ${chalk.yellow('Link Analysis:')}`);
          console.log(`    ${chalk.gray('Total Links:')} ${results.links.total}`);
          console.log(`    ${chalk.gray('Internal Links:')} ${results.links.internal.count}`);
          console.log(`    ${chalk.gray('External Links:')} ${results.links.external.count}`);
          
          if (results.links.insecure && results.links.insecure.count > 0) {
            console.log(`    ${chalk.red('⚠')} ${results.links.insecure.count} insecure links found`);
          }
        }
        
        // Show screenshot information if available
        if (results.screenshot && results.screenshot.path) {
          console.log(`\n  ${chalk.yellow('Screenshot:')} ${results.screenshot.path}`);
        }
      }
      
      // Save to file if output path provided
      if (options.output) {
        const outputPath = path.resolve(options.output);
        await fs.promises.writeFile(outputPath, JSON.stringify(results, null, 2));
        console.log(chalk.green(`\nResults saved to ${outputPath}`));
      }
      
    } catch (error) {
      spinner.fail('Web scan failed');
      console.error(chalk.red(`Error: ${error.message}`));
      if (error.stack) {
        console.error(chalk.gray(error.stack));
      }
      process.exit(1);
    }
  });

// Help functions for colorizing output
function colorizeScore(score, max = 100) {
  const percentage = max === 100 ? score : (score / max) * 100;
  if (percentage >= 80) return chalk.green(`${score}/${max}`);
  if (percentage >= 60) return chalk.yellow(`${score}/${max}`);
  return chalk.red(`${score}/${max}`);
}

function colorizeRiskLevel(level) {
  switch (level) {
    case 'Critical': return chalk.bgRed.white(' CRITICAL ');
    case 'High': return chalk.red(' HIGH ');
    case 'Medium': return chalk.yellow(' MEDIUM ');
    case 'Low': return chalk.green(' LOW ');
    default: return chalk.gray(` ${level.toUpperCase()} `);
  }
}

function colorizeSeverity(severity) {
  switch (severity) {
    case 'Critical': return chalk.bgRed.white('[CRITICAL]');
    case 'High': return chalk.red('[HIGH]');
    case 'Medium': return chalk.yellow('[MEDIUM]');
    case 'Low': return chalk.green('[LOW]');
    default: return chalk.gray(`[${severity.toUpperCase()}]`);
  }
}

/**
 * Helper function to display scan results in table format
 * @param {object} results - Scan results object
 */
function displayTableResults(results) {
  console.log('\n' + chalk.blue.bold('Target:'), results.target);
  
  if (results.ssl) {
    console.log('\n' + chalk.green('✓') + chalk.bold(' SSL/TLS:'), results.ssl.grade || 'N/A');
    console.log(chalk.gray(`  Valid: ${results.ssl.valid ? 'Yes' : 'No'}`));
    console.log(chalk.gray(`  Expires: ${results.ssl.validTo || 'N/A'}`));
  }
  
  if (results.headers && results.headers.security) {
    console.log('\n' + chalk.bold('🔒 Security Headers:'));
    for (const [header, value] of Object.entries(results.headers.security)) {
      const icon = value.enabled ? chalk.green('✓') : chalk.red('✗');
      console.log(`  ${icon} ${header}`);
    }
  }
  
  if (results.techStack) {
    console.log('\n' + chalk.bold('💻 Technology Stack:'));
    for (const category of Object.keys(results.techStack)) {
      if (results.techStack[category].length > 0) {
        console.log(chalk.gray(`  ${category}:`));
        results.techStack[category].forEach(tech => {
          console.log(`    - ${tech.name}${tech.version ? ' ' + tech.version : ''}`);
        });
      }
    }
  }
  
  if (results.cookies && results.cookies.length > 0) {
    console.log('\n' + chalk.bold('🍪 Cookies:'));
    results.cookies.forEach(cookie => {
      const secureIcon = cookie.secure ? chalk.green('✓') : chalk.red('✗');
      const httpOnlyIcon = cookie.httpOnly ? chalk.green('✓') : chalk.red('✗');
      console.log(`  - ${cookie.name}: Secure: ${secureIcon} HttpOnly: ${httpOnlyIcon}`);
    });
  }
  
  if (results.vulnerabilities && results.vulnerabilities.length > 0) {
    console.log('\n' + chalk.red.bold('⚠️ Vulnerabilities:'));
    results.vulnerabilities.forEach(vuln => {
      console.log(`  - ${chalk.red(vuln.severity.toUpperCase())}: ${vuln.title}`);
      console.log(`    ${chalk.gray(vuln.description)}`);
    });
  }
  
  // Display AI-powered insights if available
  if (results.aiInsights && results.aiInsights.length > 0) {
    console.log('\n' + chalk.blue.bold('🧠 AI Insights:'));
    results.aiInsights.forEach(insight => {
      console.log(`  - ${chalk.yellow(insight.title)}`);
      console.log(`    ${chalk.gray(insight.description)}`);
    });
  }
  
  // Display API security results if available
  if (results.apiSecurity) {
    console.log('\n' + chalk.cyan.bold('🔍 API Security:'));
    if (results.apiSecurity.endpoints && results.apiSecurity.endpoints.length > 0) {
      console.log(`  Endpoints discovered: ${results.apiSecurity.endpoints.length}`);
      console.log(`  Vulnerabilities found: ${results.apiSecurity.vulnerabilities?.length || 0}`);
    } else {
      console.log('  No API endpoints discovered');
    }
  }
  
  // Display auth security results if available
  if (results.authSecurity) {
    console.log('\n' + chalk.yellow.bold('🔑 Auth Security:'));
    const rating = results.authSecurity.rating || 'Unknown';
    const ratingColor = rating === 'Good' ? chalk.green : 
                       rating === 'Medium' ? chalk.yellow : chalk.red;
    console.log(`  Rating: ${ratingColor(rating)}`);
    console.log(`  Issues found: ${results.authSecurity.issues?.length || 0}`);
  }
  
  // Display cloud security results if available
  if (results.cloudSecurity) {
    console.log('\n' + chalk.magenta.bold('☁️ Cloud Security:'));
    console.log(`  Resources analyzed: ${results.cloudSecurity.resourcesAnalyzed || 0}`);
    console.log(`  Misconfigurations found: ${results.cloudSecurity.misconfigurations?.length || 0}`);
  }
  
  // Display dependency security results if available
  if (results.dependencySecurity) {
    console.log('\n' + chalk.yellowBright.bold('📦 Dependency Security:'));
    console.log(`  Dependencies analyzed: ${results.dependencySecurity.analyzed || 0}`);
    console.log(`  Vulnerabilities found: ${results.dependencySecurity.vulnerabilities?.length || 0}`);
    if (results.dependencySecurity.outdated > 0) {
      console.log(`  Outdated dependencies: ${results.dependencySecurity.outdated}`);
    }
  }
}

program.parse(process.argv);

// Show help if no arguments provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
