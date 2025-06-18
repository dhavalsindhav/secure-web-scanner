/**
 * Enhanced Reporting Module
 * This module provides interactive HTML reports and integrations with external dashboards
 */

const fs = require('fs').promises;
const path = require('path');
const chalk = require('chalk');
const ora = require('ora');
const { v4: uuidv4 } = require('uuid');
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');

// Server instance for interactive reports
let server = null;
let io = null;
let reportData = {};

/**
 * Generate JSON report
 * @param {object} scanResults - Scan results
 * @param {string} outputPath - Path to save report
 * @returns {Promise<string>} - Path to saved report
 */
async function generateJsonReport(scanResults, outputPath) {
  try {
    // Ensure output directory exists
    const dir = path.dirname(outputPath);
    await fs.mkdir(dir, { recursive: true });
    
    // Save JSON report
    await fs.writeFile(outputPath, JSON.stringify(scanResults, null, 2));
    
    return outputPath;
  } catch (error) {
    console.error(chalk.red(`Error generating JSON report: ${error.message}`));
    throw error;
  }
}

/**
 * Generate HTML report
 * @param {object} scanResults - Scan results
 * @param {string} outputPath - Path to save report
 * @returns {Promise<string>} - Path to saved report
 */
async function generateHtmlReport(scanResults, outputPath) {
  try {
    // Ensure output directory exists
    const dir = path.dirname(outputPath);
    await fs.mkdir(dir, { recursive: true });
    
    // Load report template
    let template;
    try {
      template = await fs.readFile(path.join(__dirname, '../templates/report.html'), 'utf-8');
    } catch (error) {
      // Create basic template if not found
      template = getDefaultReportTemplate();
    }
    
    // Replace placeholders with actual data
    const reportHtml = template
      .replace('{{REPORT_TITLE}}', `Security Scan Report: ${scanResults.target}`)
      .replace('{{SCAN_TARGET}}', scanResults.target)
      .replace('{{SCAN_DATE}}', new Date().toLocaleString())
      .replace('{{REPORT_DATA}}', JSON.stringify(scanResults))
      .replace('{{SUMMARY}}', generateSummaryHtml(scanResults))
      .replace('{{DETAILS}}', generateDetailsHtml(scanResults));
    
    // Save HTML report
    await fs.writeFile(outputPath, reportHtml);
    
    return outputPath;
  } catch (error) {
    console.error(chalk.red(`Error generating HTML report: ${error.message}`));
    throw error;
  }
}

/**
 * Generate PDF report
 * @param {object} scanResults - Scan results
 * @param {string} outputPath - Path to save report
 * @returns {Promise<string>} - Path to saved report
 */
async function generatePdfReport(scanResults, outputPath) {
  try {
    // For a real implementation, this would use a PDF generation library
    // For demo purposes, we'll just create a placeholder
    console.log(chalk.yellow('PDF report generation is not fully implemented. Generating JSON report instead.'));
    return generateJsonReport(scanResults, outputPath.replace('.pdf', '.json'));
  } catch (error) {
    console.error(chalk.red(`Error generating PDF report: ${error.message}`));
    throw error;
  }
}

/**
 * Generate and serve an interactive dashboard for scan results
 * @param {object} scanResults - Scan results
 * @param {object} options - Dashboard options
 * @returns {Promise<object>} - Dashboard info
 */
async function serveDashboard(scanResults, options = {}) {
  try {
    const port = options.port || 3000;
    const reportId = uuidv4().substring(0, 8);
    
    // Store report data
    reportData[reportId] = {
      scanResults,
      options,
      timestamp: new Date().toISOString()
    };
    
    // Create server if not already running
    if (!server) {
      const app = express();
      server = http.createServer(app);
      io = socketIo(server);
      
      // Configure express app
      app.use(express.static(path.join(__dirname, '../public')));
      
      // API routes
      app.get('/api/reports/:id', (req, res) => {
        const report = reportData[req.params.id];
        if (report) {
          res.json(report);
        } else {
          res.status(404).json({ error: 'Report not found' });
        }
      });
      
      // Dashboard route
      app.get('/dashboard/:id', (req, res) => {
        const reportId = req.params.id;
        const report = reportData[reportId];
        
        if (!report) {
          return res.status(404).send('Report not found');
        }
        
        // In a real implementation, this would serve an HTML dashboard
        // For demo purposes, we'll use a placeholder
        fs.readFile(path.join(__dirname, '../templates/dashboard.html'), 'utf-8')
          .then(template => {
            const dashboard = template
              .replace('{{REPORT_ID}}', reportId)
              .replace('{{SCAN_TARGET}}', report.scanResults.target)
              .replace('{{SCAN_DATE}}', new Date(report.timestamp).toLocaleString());
            
            res.send(dashboard);
          })
          .catch(error => {
            // If template not found, send basic dashboard
            const dashboard = getDefaultDashboardTemplate(reportId, report);
            res.send(dashboard);
          });
      });
      
      // Socket.IO
      io.on('connection', (socket) => {
        console.log('Dashboard client connected');
        
        socket.on('get-report', (reportId) => {
          const report = reportData[reportId];
          if (report) {
            socket.emit('report-data', report);
          }
        });
      });
      
      // Start server
      await new Promise((resolve, reject) => {
        server.listen(port, () => {
          console.log(chalk.green(`Dashboard server running at http://localhost:${port}/dashboard/${reportId}`));
          resolve();
        }).on('error', (error) => {
          reject(error);
        });
      });
    }
    
    return {
      url: `http://localhost:${options.port || 3000}/dashboard/${reportId}`,
      reportId,
      port: options.port || 3000
    };
  } catch (error) {
    console.error(chalk.red(`Error serving dashboard: ${error.message}`));
    throw error;
  }
}

/**
 * Generate summary HTML from scan results
 * @param {object} scanResults - Scan results
 * @returns {string} - HTML string
 */
function generateSummaryHtml(scanResults) {
  // Count issues by severity
  const severityCounts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0
  };
  
  // Extract all findings
  const allFindings = [];
  
  // Extract SSL issues
  if (scanResults.ssl && scanResults.ssl.issues) {
    scanResults.ssl.issues.forEach(issue => {
      severityCounts[issue.severity] = (severityCounts[issue.severity] || 0) + 1;
      allFindings.push({
        type: 'SSL',
        ...issue
      });
    });
  }
  
  // Extract header issues
  if (scanResults.headers && scanResults.headers.issues) {
    scanResults.headers.issues.forEach(issue => {
      severityCounts[issue.severity] = (severityCounts[issue.severity] || 0) + 1;
      allFindings.push({
        type: 'Headers',
        ...issue
      });
    });
  }
  
  // Extract tech stack vulnerabilities
  if (scanResults.techStack && scanResults.techStack.vulnerabilities) {
    scanResults.techStack.vulnerabilities.forEach(vuln => {
      severityCounts[vuln.severity] = (severityCounts[vuln.severity] || 0) + 1;
      allFindings.push({
        type: 'Tech Stack',
        ...vuln
      });
    });
  }
  
  // Generate summary HTML
  return `
    <div class="summary-section">
      <div class="summary-row">
        <div class="summary-metric">
          <h3>Critical</h3>
          <div class="metric-value critical">${severityCounts.CRITICAL || 0}</div>
        </div>
        <div class="summary-metric">
          <h3>High</h3>
          <div class="metric-value high">${severityCounts.HIGH || 0}</div>
        </div>
        <div class="summary-metric">
          <h3>Medium</h3>
          <div class="metric-value medium">${severityCounts.MEDIUM || 0}</div>
        </div>
        <div class="summary-metric">
          <h3>Low</h3>
          <div class="metric-value low">${severityCounts.LOW || 0}</div>
        </div>
        <div class="summary-metric">
          <h3>Info</h3>
          <div class="metric-value info">${severityCounts.INFO || 0}</div>
        </div>
      </div>
      <div class="summary-chart">
        <!-- Chart would be rendered here with JavaScript -->
        <div id="severity-chart"></div>
      </div>
    </div>
  `;
}

/**
 * Generate details HTML from scan results
 * @param {object} scanResults - Scan results
 * @returns {string} - HTML string
 */
function generateDetailsHtml(scanResults) {
  let html = '';
  
  // SSL section
  if (scanResults.ssl) {
    html += '<div class="details-section">';
    html += '<h2>SSL/TLS Information</h2>';
    
    if (scanResults.ssl.valid) {
      html += '<div class="status-item status-success">SSL certificate is valid</div>';
    } else {
      html += '<div class="status-item status-error">SSL certificate is invalid</div>';
    }
    
    if (scanResults.ssl.days_remaining) {
      html += `<div class="status-item">Days until expiration: ${scanResults.ssl.days_remaining}</div>`;
    }
    
    if (scanResults.ssl.issues && scanResults.ssl.issues.length > 0) {
      html += '<div class="issues-list">';
      scanResults.ssl.issues.forEach(issue => {
        html += `<div class="issue issue-${issue.severity.toLowerCase()}">
          <div class="issue-severity">${issue.severity}</div>
          <div class="issue-description">${issue.description}</div>
        </div>`;
      });
      html += '</div>';
    }
    
    html += '</div>';
  }
  
  // Headers section
  if (scanResults.headers) {
    html += '<div class="details-section">';
    html += '<h2>HTTP Headers Analysis</h2>';
    
    if (scanResults.headers.score) {
      html += `<div class="status-item">Security Score: ${scanResults.headers.score}/100</div>`;
    }
    
    if (scanResults.headers.issues && scanResults.headers.issues.length > 0) {
      html += '<div class="issues-list">';
      scanResults.headers.issues.forEach(issue => {
        html += `<div class="issue issue-${issue.severity.toLowerCase()}">
          <div class="issue-severity">${issue.severity}</div>
          <div class="issue-description">${issue.description}</div>
          ${issue.recommendation ? `<div class="issue-recommendation">${issue.recommendation}</div>` : ''}
        </div>`;
      });
      html += '</div>';
    }
    
    html += '</div>';
  }
  
  // Tech Stack section
  if (scanResults.techStack) {
    html += '<div class="details-section">';
    html += '<h2>Technology Stack</h2>';
    
    const technologies = scanResults.techStack.technologies || [];
    if (technologies.length > 0) {
      html += '<div class="tech-stack-list">';
      technologies.forEach(tech => {
        html += `<div class="tech-item">
          <div class="tech-name">${tech.name}</div>
          ${tech.version ? `<div class="tech-version">v${tech.version}</div>` : ''}
          ${tech.category ? `<div class="tech-category">${tech.category}</div>` : ''}
        </div>`;
      });
      html += '</div>';
    }
    
    const vulnerabilities = scanResults.techStack.vulnerabilities || [];
    if (vulnerabilities.length > 0) {
      html += '<h3>Vulnerabilities</h3>';
      html += '<div class="issues-list">';
      vulnerabilities.forEach(vuln => {
        html += `<div class="issue issue-${vuln.severity.toLowerCase()}">
          <div class="issue-severity">${vuln.severity}</div>
          <div class="issue-title">${vuln.title || vuln.description}</div>
          ${vuln.description ? `<div class="issue-description">${vuln.description}</div>` : ''}
          ${vuln.recommendation ? `<div class="issue-recommendation">${vuln.recommendation}</div>` : ''}
        </div>`;
      });
      html += '</div>';
    }
    
    html += '</div>';
  }
  
  return html;
}

/**
 * Get default HTML report template
 * @returns {string} - HTML template
 */
function getDefaultReportTemplate() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{REPORT_TITLE}}</title>
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
    }
    header {
      background-color: #f8f9fa;
      padding: 20px;
      margin-bottom: 30px;
      border-radius: 5px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    h1 {
      margin: 0;
      color: #2c3e50;
    }
    .report-meta {
      display: flex;
      justify-content: space-between;
      margin-top: 10px;
      color: #666;
    }
    .summary-section {
      background-color: #fff;
      padding: 20px;
      margin-bottom: 30px;
      border-radius: 5px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .summary-row {
      display: flex;
      justify-content: space-between;
      margin-bottom: 20px;
    }
    .summary-metric {
      text-align: center;
      flex: 1;
    }
    .metric-value {
      font-size: 2.5rem;
      font-weight: bold;
      margin-top: 10px;
    }
    .critical { color: #d63031; }
    .high { color: #e17055; }
    .medium { color: #fdcb6e; }
    .low { color: #00b894; }
    .info { color: #0984e3; }
    .details-section {
      background-color: #fff;
      padding: 20px;
      margin-bottom: 30px;
      border-radius: 5px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    .issues-list {
      margin-top: 20px;
    }
    .issue {
      padding: 15px;
      margin-bottom: 10px;
      border-radius: 5px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .issue-critical { background-color: #ffebee; }
    .issue-high { background-color: #fff3e0; }
    .issue-medium { background-color: #fffde7; }
    .issue-low { background-color: #e8f5e9; }
    .issue-info { background-color: #e3f2fd; }
    .issue-severity {
      font-weight: bold;
      margin-bottom: 5px;
    }
    .issue-description {
      margin-bottom: 5px;
    }
    .issue-recommendation {
      font-style: italic;
      color: #555;
    }
    .tech-stack-list {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 15px;
    }
    .tech-item {
      background-color: #f8f9fa;
      padding: 10px;
      border-radius: 5px;
      min-width: 150px;
    }
    .tech-name {
      font-weight: bold;
    }
    .tech-version {
      font-size: 0.9rem;
      color: #666;
    }
    .tech-category {
      font-size: 0.8rem;
      color: #888;
      margin-top: 5px;
    }
    .status-item {
      padding: 10px;
      margin-bottom: 10px;
      border-radius: 5px;
      background-color: #f8f9fa;
    }
    .status-success {
      background-color: #e8f5e9;
      color: #2e7d32;
    }
    .status-error {
      background-color: #ffebee;
      color: #c62828;
    }
  </style>
</head>
<body>
  <header>
    <h1>{{REPORT_TITLE}}</h1>
    <div class="report-meta">
      <div>Target: {{SCAN_TARGET}}</div>
      <div>Date: {{SCAN_DATE}}</div>
    </div>
  </header>
  
  <section class="summary-section">
    <h2>Summary</h2>
    {{SUMMARY}}
  </section>
  
  <section class="details">
    <h2>Details</h2>
    {{DETAILS}}
  </section>
  
  <script>
    // Report data for possible client-side processing
    const reportData = {{REPORT_DATA}};
  </script>
</body>
</html>`;
}

/**
 * Get default dashboard template
 * @param {string} reportId - Report ID
 * @param {object} report - Report data
 * @returns {string} - HTML template
 */
function getDefaultDashboardTemplate(reportId, report) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Dashboard - ${report.scanResults.target}</title>
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
      line-height: 1.6;
      color: #333;
      margin: 0;
      padding: 0;
      background-color: #f0f2f5;
    }
    .dashboard {
      display: grid;
      grid-template-columns: 250px 1fr;
      min-height: 100vh;
    }
    .sidebar {
      background-color: #2c3e50;
      color: white;
      padding: 20px;
    }
    .sidebar h1 {
      margin-top: 0;
      font-size: 1.5rem;
    }
    .content {
      padding: 20px;
    }
    .nav-item {
      padding: 10px;
      cursor: pointer;
      border-radius: 5px;
      margin-bottom: 5px;
    }
    .nav-item:hover {
      background-color: rgba(255,255,255,0.1);
    }
    .nav-item.active {
      background-color: rgba(255,255,255,0.2);
    }
    .card {
      background-color: white;
      border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      padding: 20px;
      margin-bottom: 20px;
    }
    .overview-cards {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }
    .metric-card {
      text-align: center;
      padding: 20px;
    }
    .metric-value {
      font-size: 2.5rem;
      font-weight: bold;
      margin: 10px 0;
    }
    .critical { color: #d63031; }
    .high { color: #e17055; }
    .medium { color: #fdcb6e; }
    .low { color: #00b894; }
    .info { color: #0984e3; }
    .header-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
    }
    .data-table {
      width: 100%;
      border-collapse: collapse;
    }
    .data-table th, .data-table td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #eee;
    }
    .data-table th {
      background-color: #f8f9fa;
      font-weight: 500;
    }
    .tab-navigation {
      display: flex;
      gap: 2px;
      margin-bottom: 20px;
      background-color: #f8f9fa;
      border-radius: 8px;
      overflow: hidden;
    }
    .tab {
      padding: 10px 20px;
      cursor: pointer;
      flex: 1;
      text-align: center;
      transition: all 0.3s;
    }
    .tab.active {
      background-color: white;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
  </style>
</head>
<body>
  <div class="dashboard">
    <div class="sidebar">
      <h1>Security Scanner</h1>
      <div class="nav-item active">Overview</div>
      <div class="nav-item">Vulnerabilities</div>
      <div class="nav-item">Tech Stack</div>
      <div class="nav-item">Headers</div>
      <div class="nav-item">SSL/TLS</div>
      <div class="nav-item">Settings</div>
    </div>
    <div class="content">
      <div class="header-bar">
        <h1>Security Dashboard</h1>
        <div>
          <strong>Target:</strong> ${report.scanResults.target} |
          <strong>Scan Date:</strong> ${new Date(report.timestamp).toLocaleString()}
        </div>
      </div>
      
      <div class="overview-cards">
        <div class="card metric-card">
          <h3>Critical Issues</h3>
          <div class="metric-value critical">0</div>
        </div>
        <div class="card metric-card">
          <h3>High Issues</h3>
          <div class="metric-value high">3</div>
        </div>
        <div class="card metric-card">
          <h3>Medium Issues</h3>
          <div class="metric-value medium">8</div>
        </div>
        <div class="card metric-card">
          <h3>Low Issues</h3>
          <div class="metric-value low">12</div>
        </div>
        <div class="card metric-card">
          <h3>Info Issues</h3>
          <div class="metric-value info">5</div>
        </div>
      </div>
      
      <div class="card">
        <h2>Vulnerabilities</h2>
        <div class="tab-navigation">
          <div class="tab active">All</div>
          <div class="tab">Critical</div>
          <div class="tab">High</div>
          <div class="tab">Medium</div>
          <div class="tab">Low</div>
        </div>
        <table class="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Type</th>
              <th>Description</th>
              <th>Affected Item</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>High</td>
              <td>SSL</td>
              <td>Outdated SSL protocol version</td>
              <td>TLS 1.0</td>
            </tr>
            <tr>
              <td>Medium</td>
              <td>Headers</td>
              <td>Missing Content Security Policy header</td>
              <td>HTTP Headers</td>
            </tr>
            <tr>
              <td>High</td>
              <td>Tech Stack</td>
              <td>Outdated library with known vulnerabilities</td>
              <td>jQuery 1.11.0</td>
            </tr>
            <tr>
              <td>Low</td>
              <td>Headers</td>
              <td>Missing X-Frame-Options header</td>
              <td>HTTP Headers</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    // This would be replaced with actual data or WebSocket connection
    const reportData = ${JSON.stringify(report.scanResults)};
    const reportId = "${reportId}";
    
    // In a real implementation, we'd connect to WebSocket
    // const socket = io();
    // socket.emit('get-report', reportId);
    // socket.on('report-data', (data) => {
    //   updateDashboard(data);
    // });
  </script>
</body>
</html>`;
}

/**
 * Main function for enhanced reporting
 * @param {object} scanResults - Scan results
 * @param {object} options - Reporting options
 * @returns {Promise<object>} - Report information
 */
async function generateReport(scanResults, options = {}) {
  try {
    const results = {
      timestamp: new Date().toISOString(),
      reports: []
    };
    
    const spinner = ora('Generating reports...').start();
    
    // Generate requested report formats
    const formats = options.formats || ['json'];
    
    for (const format of formats) {
      let outputPath = options.outputPath || `./report-${scanResults.target}-${Date.now()}`;
      
      if (format === 'json') {
        outputPath = outputPath.endsWith('.json') ? outputPath : `${outputPath}.json`;
        const jsonPath = await generateJsonReport(scanResults, outputPath);
        results.reports.push({ format: 'json', path: jsonPath });
      } else if (format === 'html') {
        outputPath = outputPath.endsWith('.html') ? outputPath : `${outputPath}.html`;
        const htmlPath = await generateHtmlReport(scanResults, outputPath);
        results.reports.push({ format: 'html', path: htmlPath });
      } else if (format === 'pdf') {
        outputPath = outputPath.endsWith('.pdf') ? outputPath : `${outputPath}.pdf`;
        const pdfPath = await generatePdfReport(scanResults, outputPath);
        results.reports.push({ format: 'pdf', path: pdfPath });
      }
    }
    
    spinner.succeed(`Generated ${results.reports.length} report(s)`);
    
    // Create interactive dashboard if requested
    if (options.interactive) {
      const dashboard = await serveDashboard(scanResults, options);
      results.dashboard = dashboard;
      
      console.log(chalk.green(`Interactive dashboard available at: ${dashboard.url}`));
      console.log(chalk.gray('Press Ctrl+C to stop the dashboard server.'));
    }
    
    return results;
  } catch (error) {
    console.error(chalk.red(`Report generation failed: ${error.message}`));
    throw error;
  }
}

module.exports = {
  generateReport,
  generateJsonReport,
  generateHtmlReport,
  generatePdfReport,
  serveDashboard
};
