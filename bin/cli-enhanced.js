/**
 * Command-line interfaces for the new modules
 */

const program = require('commander');
const chalk = require('chalk');
const ora = require('ora');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

// Import required modules
const { 
  scanApi, 
  detectVulnerabilities, 
  scanCloud, 
  scanDependencies,
  generateReport,
  serveDashboard,
  analyzeAuthForm
} = require('../lib/index');

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
  .option('-p, --provider <name>', 'Cloud provider name (aws, azure, gcp)')
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

module.exports = program;
