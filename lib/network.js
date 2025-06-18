/**
 * Network scanning functionality including port scanning and service fingerprinting
 * This module integrates port scanning functionality with service fingerprinting
 */

const { scanPorts, analyzePortSecurity, PORT_GROUPS } = require('./ports');
const axios = require('axios');
const util = require('util');
const { exec } = require('child_process');
const execPromise = util.promisify(exec);

/**
 * Enhanced port scanning with service fingerprinting
 * @param {string} target - Target host/IP to scan
 * @param {object} options - Scan options
 * @returns {Promise<object>} - Port scanning results with service information
 */
async function enhancedPortScan(target, options = {}) {
  // Default options
  const defaultOptions = {
    portLevel: 'standard', // minimal, web, standard, comprehensive
    customPorts: null,     // Specific ports to scan
    timeout: 10000,        // Timeout in ms
    parallel: 10,          // Number of parallel port scans
    fingerprint: true,     // Perform service fingerprinting
    filterClosed: true     // Only return open ports in results
  };

  const scanOptions = { ...defaultOptions, ...options };
  
  // Get ports to scan based on the selected level
  let portsToScan = [];
  if (scanOptions.customPorts) {
    portsToScan = Array.isArray(scanOptions.customPorts) 
      ? scanOptions.customPorts 
      : scanOptions.customPorts.split(',').map(p => parseInt(p.trim(), 10));
  } else {
    portsToScan = PORT_GROUPS[scanOptions.portLevel] || PORT_GROUPS.minimal;
  }

  // Perform the port scan
  const portResults = await scanPorts(target, portsToScan, {
    timeout: scanOptions.timeout,
    parallel: scanOptions.parallel
  });

  // Add service fingerprinting if enabled
  if (scanOptions.fingerprint) {
    const openPorts = portResults.filter(p => p.open);
    
    // Add fingerprinting data to each open port
    for (const port of openPorts) {
      try {
        port.service = await fingerprintService(target, port.port);
      } catch (error) {
        port.service = { error: error.message };
      }
    }
  }

  // Filter results if requested
  const finalResults = scanOptions.filterClosed 
    ? portResults.filter(p => p.open)
    : portResults;

  // Add security analysis
  const analysis = analyzePortSecurity(finalResults);
  
  return {
    target,
    timestamp: new Date().toISOString(),
    summary: {
      total: portResults.length,
      open: portResults.filter(p => p.open).length,
      closed: portResults.filter(p => !p.open).length
    },
    ports: finalResults,
    analysis
  };
}

/**
 * Fingerprint service running on a specific port
 * @param {string} host - Target host/IP
 * @param {number} port - Port number
 * @returns {Promise<object>} - Service information
 */
async function fingerprintService(host, port) {
  // Try to detect HTTP/HTTPS services first with direct connection
  if ([80, 443, 8080, 8443, 3000, 8000, 8888].includes(port)) {
    try {
      const protocol = [443, 8443].includes(port) ? 'https' : 'http';
      const response = await axios.get(`${protocol}://${host}:${port}`, {
        timeout: 5000,
        maxRedirects: 0,
        validateStatus: () => true, // Accept any status code
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });
      
      // Extract service information from headers
      const server = response.headers['server'] || 'Unknown';
      const poweredBy = response.headers['x-powered-by'] || null;
      
      return {
        protocol,
        service: 'HTTP',
        product: server,
        details: poweredBy ? { 'x-powered-by': poweredBy } : {},
        headers: response.headers,
        status: response.status
      };
    } catch (error) {
      // If HTTP request fails, fall back to generic method
    }
  }
  
  // Generic service detection logic
  // This would ideally use nmap or similar tool for better fingerprinting
  const serviceMap = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    110: 'POP3',
    143: 'IMAP',
    389: 'LDAP',
    443: 'HTTPS',
    465: 'SMTPS',
    587: 'SMTP Submission',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle DB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP Proxy',
    8443: 'HTTPS Alt',
    27017: 'MongoDB'
  };
  
  return {
    service: serviceMap[port] || 'Unknown',
    port: port,
    details: {}
  };
}

module.exports = {
  enhancedPortScan,
  fingerprintService,
  PORT_GROUPS
};
