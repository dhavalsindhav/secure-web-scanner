/**
 * Helper functions for the security scanner
 */

const chalk = require('chalk');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const os = require('os');

/**
 * Format a date for display
 * @param {Date|string} date - Date to format
 * @returns {string} - Formatted date string
 */
function formatDate(date) {
  if (!date) return 'Unknown';
  const dateObj = typeof date === 'string' ? new Date(date) : date;
  return dateObj.toLocaleDateString() + ' ' + dateObj.toLocaleTimeString();
}

/**
 * Create a fingerprint of data
 * @param {object|string} data - Data to fingerprint 
 * @returns {string} - MD5 hash of the data
 */
function createFingerprint(data) {
  const content = typeof data === 'string' ? data : JSON.stringify(data);
  return crypto.createHash('md5').update(content).digest('hex');
}

/**
 * Save scan results to a file
 * @param {object} results - Scan results to save
 * @param {string} outputPath - Path to save results to (optional)
 * @returns {Promise<string>} - Path where results were saved
 */
async function saveResults(results, outputPath) {
  // If no output path specified, create one in default location
  if (!outputPath) {
    const timestamp = new Date().toISOString().replace(/:/g, '-').replace(/\..+/, '');
    const target = results.target || results.domain || 'scan';
    const sanitizedTarget = target.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    const filename = `${sanitizedTarget}_${timestamp}.json`;
    outputPath = path.join(os.tmpdir(), 'secure-web-scanner', filename);
    
    // Ensure directory exists
    const dir = path.dirname(outputPath);
    await fs.mkdir(dir, { recursive: true });
  }
  
  // Save results to file
  await fs.writeFile(outputPath, JSON.stringify(results, null, 2));
  return outputPath;
}

/**
 * Parse a list of ports from string
 * @param {string|null} portList - Comma-separated list of ports or ranges
 * @returns {number[]|null} - Array of port numbers or null
 */
function parsePortList(portList) {
  if (!portList) return null;
  
  const ports = [];
  const segments = portList.split(',');
  
  for (const segment of segments) {
    if (segment.includes('-')) {
      // Port range
      const [start, end] = segment.split('-').map(p => parseInt(p.trim(), 10));
      for (let i = start; i <= end; i++) {
        if (i > 0 && i < 65536) {
          ports.push(i);
        }
      }
    } else {
      // Single port
      const port = parseInt(segment.trim(), 10);
      if (port > 0 && port < 65536) {
        ports.push(port);
      }
    }
  }
  
  return ports.length > 0 ? [...new Set(ports)].sort((a, b) => a - b) : null;
}

/**
 * Check if a string looks like a valid URL
 * @param {string} str - String to check
 * @returns {boolean} - True if valid URL
 */
function isValidUrl(str) {
  try {
    new URL(str);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Normalize a URL (add protocol if missing)
 * @param {string} url - URL to normalize
 * @returns {string} - Normalized URL
 */
function normalizeUrl(url) {
  if (!url) return '';
  
  // Check if it already has a protocol
  if (url.match(/^[a-z]+:\/\//i)) {
    return url;
  }
  
  // Add https:// as default protocol
  return `https://${url}`;
}

/**
 * Extract domain from URL
 * @param {string} url - URL to extract domain from
 * @returns {string|null} - Domain or null if invalid
 */
function extractDomain(url) {
  try {
    const normalizedUrl = normalizeUrl(url);
    const urlObj = new URL(normalizedUrl);
    return urlObj.hostname;
  } catch (e) {
    // If it's not a valid URL, check if it's a domain
    if (/^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i.test(url)) {
      return url;
    }
    return null;
  }
}

/**
 * Format a security score for display
 * @param {number} score - Score to format
 * @param {number} max - Maximum possible score
 * @returns {string} - Formatted and colored score string
 */
function formatScore(score, max = 100) {
  const percentage = max === 100 ? score : (score / max) * 100;
  if (percentage >= 80) return chalk.green(`${score}/${max}`);
  if (percentage >= 60) return chalk.yellow(`${score}/${max}`);
  return chalk.red(`${score}/${max}`);
}

/**
 * Format a risk level for display
 * @param {string} level - Risk level (Critical, High, Medium, Low)
 * @returns {string} - Formatted and colored risk level string
 */
function formatRiskLevel(level) {
  switch (level) {
    case 'Critical': return chalk.bgRed.white(' CRITICAL ');
    case 'High': return chalk.red(' HIGH ');
    case 'Medium': return chalk.yellow(' MEDIUM ');
    case 'Low': return chalk.green(' LOW ');
    default: return chalk.gray(` ${level.toUpperCase()} `);
  }
}

/**
 * Format a vulnerability severity for display
 * @param {string} severity - Severity level
 * @returns {string} - Formatted and colored severity string
 */
function formatSeverity(severity) {
  switch (severity) {
    case 'Critical': return chalk.bgRed.white('[CRITICAL]');
    case 'High': return chalk.red('[HIGH]');
    case 'Medium': return chalk.yellow('[MEDIUM]');
    case 'Low': return chalk.green('[LOW]');
    default: return chalk.gray(`[${severity.toUpperCase()}]`);
  }
}

/**
 * Convert bytes to human-readable format
 * @param {number} bytes - Bytes to format
 * @returns {string} - Formatted string (e.g. "1.23 MB")
 */
function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Get cache directory for saving temporary files
 * @returns {Promise<string>} - Path to cache directory
 */
async function getCacheDir() {
  const cacheDir = path.join(os.tmpdir(), 'secure-web-scanner');
  await fs.mkdir(cacheDir, { recursive: true });
  return cacheDir;
}

module.exports = {
  formatDate,
  createFingerprint,
  saveResults,
  parsePortList,
  isValidUrl,
  normalizeUrl,
  extractDomain,
  formatScore,
  formatRiskLevel,
  formatSeverity,
  formatBytes,
  getCacheDir
};
