/**
 * Port Scanner Module
 * Scans for open ports and identifies potential security issues
 */
const net = require('net');
const portScanner = require('node-port-scanner');
const axios = require('axios');

// Common ports and their services
const COMMON_PORTS = {
  21: { service: 'FTP', secure: false, critical: false, description: 'File Transfer Protocol' },
  22: { service: 'SSH', secure: true, critical: false, description: 'Secure Shell' },
  23: { service: 'Telnet', secure: false, critical: true, description: 'Unencrypted terminal access' },
  25: { service: 'SMTP', secure: false, critical: false, description: 'Simple Mail Transfer Protocol' },
  53: { service: 'DNS', secure: false, critical: false, description: 'Domain Name System' },
  80: { service: 'HTTP', secure: false, critical: false, description: 'Hypertext Transfer Protocol' },
  110: { service: 'POP3', secure: false, critical: false, description: 'Post Office Protocol v3' },
  111: { service: 'RPC', secure: false, critical: true, description: 'Remote Procedure Call' },
  135: { service: 'RPC', secure: false, critical: true, description: 'Microsoft RPC' },
  139: { service: 'NetBIOS', secure: false, critical: true, description: 'NetBIOS Session Service' },
  143: { service: 'IMAP', secure: false, critical: false, description: 'Internet Message Access Protocol' },
  389: { service: 'LDAP', secure: false, critical: true, description: 'Lightweight Directory Access Protocol' },
  443: { service: 'HTTPS', secure: true, critical: false, description: 'HTTP Secure' },
  445: { service: 'SMB', secure: false, critical: true, description: 'Server Message Block' },
  465: { service: 'SMTPS', secure: true, critical: false, description: 'SMTP over SSL' },
  587: { service: 'SMTP', secure: false, critical: false, description: 'SMTP Submission' },
  636: { service: 'LDAPS', secure: true, critical: true, description: 'LDAP over SSL' },
  993: { service: 'IMAPS', secure: true, critical: false, description: 'IMAP over SSL' },
  995: { service: 'POP3S', secure: true, critical: false, description: 'POP3 over SSL' },
  1433: { service: 'MSSQL', secure: false, critical: true, description: 'Microsoft SQL Server' },
  1521: { service: 'Oracle DB', secure: false, critical: true, description: 'Oracle Database' },
  2049: { service: 'NFS', secure: false, critical: true, description: 'Network File System' },
  2375: { service: 'Docker', secure: false, critical: true, description: 'Docker API (unencrypted)' },
  2376: { service: 'Docker', secure: true, critical: true, description: 'Docker API (SSL)' },
  3000: { service: 'Dev Server', secure: false, critical: false, description: 'Common development server port' },
  3306: { service: 'MySQL', secure: false, critical: true, description: 'MySQL Database' },
  3389: { service: 'RDP', secure: true, critical: true, description: 'Remote Desktop Protocol' },
  5432: { service: 'PostgreSQL', secure: false, critical: true, description: 'PostgreSQL Database' },
  5900: { service: 'VNC', secure: false, critical: true, description: 'Virtual Network Computing' },
  6379: { service: 'Redis', secure: false, critical: true, description: 'Redis Database' },
  8000: { service: 'Alt HTTP', secure: false, critical: false, description: 'Alternate HTTP port' },
  8080: { service: 'HTTP Alt', secure: false, critical: false, description: 'Alternative HTTP port' },
  8443: { service: 'HTTPS Alt', secure: true, critical: false, description: 'Alternative HTTPS port' },
  8888: { service: 'Alt HTTP', secure: false, critical: false, description: 'Alternate HTTP port' },
  9000: { service: 'Alt HTTP', secure: false, critical: false, description: 'Alternate HTTP port' },
  9090: { service: 'Alt HTTP', secure: false, critical: false, description: 'Alternate HTTP port' },
  9200: { service: 'Elasticsearch', secure: false, critical: true, description: 'Elasticsearch' },
  10000: { service: 'Webmin', secure: false, critical: true, description: 'Webmin admin interface' },
  27017: { service: 'MongoDB', secure: false, critical: true, description: 'MongoDB Database' },
  27018: { service: 'MongoDB', secure: false, critical: true, description: 'MongoDB Shard' }
};

// Groups of ports for different scan types
const PORT_GROUPS = {
  minimal: [80, 443], // Minimal scan (just web ports)
  web: [80, 443, 3000, 8000, 8080, 8443, 8888, 9000, 9090], // Common web ports
  database: [1433, 1521, 3306, 5432, 6379, 27017, 27018, 9200], // Database ports
  admin: [22, 23, 3389, 5900, 2375, 2376, 10000], // Admin/remote access ports
  mail: [25, 110, 143, 465, 587, 993, 995], // Mail related ports
  standard: [21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 3306, 3389, 8080, 8443], // Standard scan
  comprehensive: Object.keys(COMMON_PORTS).map(Number) // All ports in our list
};

/**
 * Attempt to fingerprint service on an open port
 * @param {string} host - Host to connect to
 * @param {number} port - Port number
 * @returns {Promise<object>} - Fingerprint result
 */
async function fingerprint(host, port) {
  const result = {
    banner: null,
    protocol: null
  };
  
  // Try HTTP(S) fingerprinting first for common web ports
  if ([80, 443, 8000, 8080, 8443, 3000, 8888, 9000, 9090].includes(port)) {
    try {
      const protocol = port === 443 || port === 8443 ? 'https' : 'http';
      const response = await axios.get(`${protocol}://${host}:${port}`, {
        timeout: 5000,
        validateStatus: null,
        maxRedirects: 0,
        headers: {
          'User-Agent': 'Mozilla/5.0 secure-web-scanner/1.0.0'
        }
      });
      
      if (response.headers) {
        result.banner = response.headers.server || response.headers['x-powered-by'] || null;
        result.protocol = protocol.toUpperCase();
        result.headers = {};
        
        // Copy important headers for fingerprinting
        const importantHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-frame-options'];
        for (const header of importantHeaders) {
          if (response.headers[header]) {
            result.headers[header] = response.headers[header];
          }
        }
      }
      
      return result;
    } catch (error) {
      // Fall back to TCP socket probe on HTTP failure
    }
  }
  
  // TCP socket probe for banner grabbing
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(3000);
    let banner = '';
    
    socket.on('data', (data) => {
      banner += data.toString().trim();
      socket.end();
    });
    
    socket.on('error', () => {
      socket.destroy();
      resolve(result);
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve(result);
    });
    
    socket.on('close', () => {
      if (banner) {
        result.banner = banner.split('\n')[0]; // Just the first line of the banner
      }
      resolve(result);
    });
    
    try {
      socket.connect(port, host);
      
      // Send different probes based on port
      if (port === 21) socket.write('HELP\r\n'); // FTP
      else if (port === 25 || port === 587 || port === 465) socket.write('EHLO secure-web-scanner\r\n'); // SMTP
      else if (port === 110) socket.write('CAPA\r\n'); // POP3
      else if (port === 143) socket.write('A1 CAPABILITY\r\n'); // IMAP
      else socket.write('\r\n'); // Generic probe
    } catch (e) {
      socket.destroy();
      resolve(result);
    }
  });
}

/**
 * Scan a subset of common ports on a host
 * @param {string} host - Host to scan
 * @param {Array|string} ports - Optional specific ports to scan or a preset name
 * @param {number} timeout - Timeout in ms
 * @param {boolean} fingerprint - Whether to fingerprint services
 * @returns {Promise<object>} - Port scanning results
 */
async function scanPorts(host, ports = null, timeout = 3000, doFingerprint = false) {
  let portsToScan;
  
  // Handle port group presets
  if (typeof ports === 'string' && PORT_GROUPS[ports]) {
    portsToScan = PORT_GROUPS[ports];
  } 
  // Handle numeric port arrays
  else if (Array.isArray(ports)) {
    portsToScan = ports;
  }
  // Default to minimal scan
  else {
    portsToScan = PORT_GROUPS.minimal;
  }
  
  try {
    // Clean host from URL if needed
    if (host.startsWith('http://') || host.startsWith('https://')) {
      host = new URL(host).hostname;
    }
      // Perform the scan
    const results = await portScanner(host, portsToScan, timeout);
    
    // Format results - ensure we always have arrays
    const openPorts = results.open && Array.isArray(results.open) ? results.open : [];
    const closedPorts = results.closed && Array.isArray(results.closed) ? results.closed : [];
    
    console.log(`Scanning ${host} for ports: ${portsToScan.join(', ')}`);
    if (openPorts.length > 0) {
      console.log(`Open ports found: ${openPorts.join(', ')}`);
    } else {
      console.log(`No open ports found`);
    }
    
    const portDetails = {};
    
    // Add details for open ports
    for (const port of openPorts) {
      portDetails[port] = COMMON_PORTS[port] || { 
        service: 'Unknown',
        secure: false,
        critical: false,
        description: 'Unknown service'
      };
      
      // Try to fingerprint the service if requested
      if (doFingerprint) {
        try {
          const fingerPrintData = await fingerprint(host, port);
          portDetails[port].fingerprint = fingerPrintData;
        } catch (error) {
          // Failed fingerprint doesn't affect the scan
          portDetails[port].fingerprint = { error: 'Fingerprinting failed' };
        }
      }
    }
      return {
      host,
      scanned: portsToScan,
      open: openPorts,
      closed: closedPorts,
      portDetails,
      summary: `${openPorts.length} open of ${portsToScan.length} ports scanned`
    };
  } catch (error) {
    return {
      host,
      error: true,
      message: error.message
    };
  }
}

/**
 * Analyze port scanning results for security issues
 * @param {object} scanResults - Results from scanPorts
 * @returns {object} - Security analysis
 */
function analyzePortSecurity(scanResults) {
  if (scanResults.error) {
    return {
      status: 'error',
      message: scanResults.message,
      issues: [],
      warnings: [],
      recommendations: [],
      score: 0,
      percentage: 0
    };
  }
    const issues = [];
  const warnings = [];
  const recommendations = [];
  const portDetailsArray = [];
  
  // Check for insecure open ports
  // Ensure openPorts is an array to prevent "is not iterable" error
  const openPorts = Array.isArray(scanResults.open) ? scanResults.open : [];
  
  for (const port of openPorts) {
    const portDetail = scanResults.portDetails && scanResults.portDetails[port];
    
    if (portDetail) {
      // Add detailed information for reporting
      const detailObj = {
        port,
        service: portDetail.service,
        description: portDetail.description || '',
        critical: portDetail.critical,
        secure: portDetail.secure,
        fingerprint: portDetail.fingerprint || null
      };
      
      portDetailsArray.push(detailObj);      
      // Generate findings based on port criticality
      if (portDetail.critical) {
        if (!portDetail.secure) {
          issues.push(`Port ${port} (${portDetail.service}) is open and potentially insecure`);
          recommendations.push(`Close or restrict access to port ${port} (${portDetail.service}) if not required`);
        } else {
          warnings.push(`Port ${port} (${portDetail.service}) is open - ensure it's properly secured`);
          recommendations.push(`Verify that ${portDetail.service} on port ${port} is configured securely`);
        }
      } else if (!portDetail.secure) {
        warnings.push(`Port ${port} (${portDetail.service}) is open and uses an unencrypted protocol`);
        recommendations.push(`Consider using a secure alternative to ${portDetail.service} on port ${port}`);
      }
      
      // Service-specific recommendations
      if (portDetail.service === 'FTP' && !portDetail.secure) {
        recommendations.push(`Replace FTP (port ${port}) with SFTP or FTPS for secure file transfers`);
      } else if (portDetail.service === 'Telnet') {
        recommendations.push(`Replace Telnet (port ${port}) with SSH for secure terminal access`);
      } else if (['MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'Elasticsearch'].includes(portDetail.service)) {
        recommendations.push(`Ensure ${portDetail.service} (port ${port}) is not exposed to the public internet`);
      }
      
      // Banner-specific warnings
      if (portDetail.fingerprint && portDetail.fingerprint.banner) {
        const banner = portDetail.fingerprint.banner;
        
        // Look for version information that might indicate outdated software
        const versionMatch = banner.match(/[\/\s](\d+\.\d+\.?\d*)/);
        if (versionMatch) {
          warnings.push(`${details.service} on port ${port} reveals version information: ${versionMatch[1]}`);
          recommendations.push(`Configure ${details.service} to hide version information`);
        }
      }
    }
  }
  
  // Calculate security score
  const maxScore = 100;
  let score = maxScore;
  
  // Default to a reasonable score when no ports are found open
  if (openPorts.length === 0) {
    score = 95; // No open ports is good, but we don't have confirmation of scanning accuracy
  } else {
    // Each critical insecure open port -20
    const criticalInsecure = openPorts.filter(port => {
      const details = scanResults.portDetails && scanResults.portDetails[port];
      return details && details.critical && !details.secure;
    });
    score -= criticalInsecure.length * 20;
    
    // Each critical secure open port -5
    const criticalSecure = openPorts.filter(port => {
      const details = scanResults.portDetails && scanResults.portDetails[port];
      return details && details.critical && details.secure;
    });
    score -= criticalSecure.length * 5;
    
    // Each non-critical insecure open port -10
    const nonCriticalInsecure = openPorts.filter(port => {
      const details = scanResults.portDetails && scanResults.portDetails[port];
      return details && !details.critical && !details.secure;
    });
    score -= nonCriticalInsecure.length * 10;
    
    // Web ports are expected to be open
    if (openPorts.includes(80) || openPorts.includes(443)) {
      score += 10;
    }
    
    // Too many open ports is a general concern
    if (openPorts.length > 5) {
      warnings.push(`High number of open ports detected (${openPorts.length})`);
      recommendations.push('Review and close unnecessary services to reduce attack surface');
      score -= Math.min(20, (openPorts.length - 5) * 2);
    }
  }

  // Normalize score between 0-100
  score = Math.max(0, Math.min(100, Math.round(score)));
  
  // Add high-level summary
  let summary = '';
  if (openPorts.length > 0) {
    summary = `${openPorts.length} open ports detected. `;
    
    const criticalInsecure = openPorts.filter(port => {
      const details = scanResults.portDetails && scanResults.portDetails[port];
      return details && details.critical && !details.secure;
    });
    
    const criticalSecure = openPorts.filter(port => {
      const details = scanResults.portDetails && scanResults.portDetails[port];
      return details && details.critical && details.secure;
    });
    
    if (criticalInsecure.length > 0) {
      summary += `${criticalInsecure.length} critical insecure services. `;
    }
    
    if (criticalSecure.length > 0) {
      summary += `${criticalSecure.length} critical secure services. `;
    }
  } else {
    summary = 'No open ports detected in scan range.';
  }
  
  // Deduplicate recommendations
  const uniqueRecommendations = [...new Set(recommendations)];    return {
    status: issues.length > 0 ? 'issues' : warnings.length > 0 ? 'warnings' : 'secure',
    score,
    percentage: score,
    issues,
    warnings,
    recommendations: uniqueRecommendations,
    details: portDetailsArray,
    summary,
    openPortCount: openPorts.length
  };
}

module.exports = { 
  scanPorts, 
  analyzePortSecurity, 
  COMMON_PORTS,
  PORT_GROUPS,
  fingerprint
};
