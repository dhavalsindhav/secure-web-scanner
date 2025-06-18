/**
 * Supply Chain Security Module
 * This module analyzes package dependencies for vulnerabilities and supply chain risks
 */

const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');
const chalk = require('chalk');
const ora = require('ora');
const semver = require('semver');

// Common package vulnerability databases
// In a real implementation, this would call actual vulnerability databases
const VULNERABILITY_SOURCES = {
  NPM: 'https://registry.npmjs.org/-/npm/v1/security/advisories',
  GITHUB: 'https://api.github.com/graphql',
  SNYK: 'https://api.snyk.io/v1'
};

/**
 * Analyze package.json for dependencies and vulnerabilities
 * @param {string} filePath - Path to package.json file
 * @param {object} options - Analysis options
 * @returns {Promise<object>} - Analysis results
 */
async function analyzeNodePackage(filePath, options = {}) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const packageJson = JSON.parse(content);
    
    const result = {
      file: filePath,
      packageName: packageJson.name || 'unknown',
      packageVersion: packageJson.version || 'unknown',
      dependencies: {
        production: Object.keys(packageJson.dependencies || {}).length,
        development: Object.keys(packageJson.devDependencies || {}).length,
        optional: Object.keys(packageJson.optionalDependencies || {}).length,
        peer: Object.keys(packageJson.peerDependencies || {}).length,
      },
      directDependencies: {},
      vulnerabilities: [],
      license: packageJson.license || 'unknown'
    };
    
    // Extract direct dependencies
    const allDependencies = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies,
      ...packageJson.optionalDependencies
    };
    
    for (const [name, version] of Object.entries(allDependencies)) {
      result.directDependencies[name] = {
        name,
        version: version.replace(/[^\d.]/g, ''), // Clean version string
        isDev: !!packageJson.devDependencies?.[name],
        isOptional: !!packageJson.optionalDependencies?.[name]
      };
    }
    
    // Check for vulnerabilities in dependencies
    if (options.checkVulnerabilities !== false) {
      const vulnerabilities = await checkPackageVulnerabilities(
        result.directDependencies,
        options
      );
      
      result.vulnerabilities = vulnerabilities;
    }
    
    // Check for license issues
    if (options.checkLicenses !== false) {
      result.licenseIssues = await checkLicenseIssues(result.directDependencies);
    }
    
    // Check lockfile if exists
    const lockfilePath = path.join(path.dirname(filePath), 'package-lock.json');
    try {
      await fs.access(lockfilePath);
      result.hasLockfile = true;
      
      if (options.checkLockfile !== false) {
        const lockfileIssues = await checkLockfileIssues(lockfilePath);
        result.lockfileIssues = lockfileIssues;
      }
    } catch {
      result.hasLockfile = false;
      result.lockfileIssues = [{ 
        type: 'MISSING_LOCKFILE', 
        severity: 'MEDIUM',
        description: 'No package-lock.json found. Lock files help prevent unexpected package updates.',
        recommendation: 'Generate a package-lock.json by running npm install'
      }];
    }
    
    return result;
  } catch (error) {
    console.error(chalk.red(`Error analyzing Node.js package: ${error.message}`));
    return { file: filePath, error: error.message, vulnerabilities: [] };
  }
}

/**
 * Analyze Python requirements.txt for dependencies and vulnerabilities
 * @param {string} filePath - Path to requirements.txt file
 * @param {object} options - Analysis options
 * @returns {Promise<object>} - Analysis results
 */
async function analyzePythonRequirements(filePath, options = {}) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const lines = content.split('\n').filter(line => line.trim() && !line.trim().startsWith('#'));
    
    const result = {
      file: filePath,
      dependencies: lines.length,
      directDependencies: {},
      vulnerabilities: []
    };
    
    // Parse requirements.txt
    for (const line of lines) {
      const match = line.match(/^([A-Za-z0-9_.-]+)(?:[=<>!]=?|@)([0-9A-Za-z.-]+)/);
      if (match) {
        const [, name, version] = match;
        result.directDependencies[name.toLowerCase()] = {
          name,
          version,
          raw: line
        };
      } else if (line.trim()) {
        // Simple package name without version
        const packageName = line.trim();
        result.directDependencies[packageName.toLowerCase()] = {
          name: packageName,
          version: 'latest',
          raw: line
        };
      }
    }
    
    // Check for vulnerabilities in dependencies
    if (options.checkVulnerabilities !== false) {
      const vulnerabilities = await checkPythonPackageVulnerabilities(
        result.directDependencies,
        options
      );
      
      result.vulnerabilities = vulnerabilities;
    }
    
    return result;
  } catch (error) {
    console.error(chalk.red(`Error analyzing Python requirements: ${error.message}`));
    return { file: filePath, error: error.message, vulnerabilities: [] };
  }
}

/**
 * Check for vulnerabilities in Node.js packages
 * @param {object} dependencies - Dependencies object
 * @param {object} options - Checking options
 * @returns {Promise<Array>} - List of vulnerabilities
 */
async function checkPackageVulnerabilities(dependencies, options = {}) {
  // In a real implementation, this would call an actual vulnerability database API
  // For demo purposes, we'll check a few common packages with known issues
  
  const vulnerabilities = [];
  const knownVulnerablePackages = {
    'lodash': [
      { versions: '<4.17.20', severity: 'HIGH', description: 'Prototype Pollution', cve: 'CVE-2020-8203' },
      { versions: '<4.17.12', severity: 'MEDIUM', description: 'Prototype Pollution', cve: 'CVE-2019-10744' }
    ],
    'axios': [
      { versions: '<0.21.1', severity: 'HIGH', description: 'Server-Side Request Forgery', cve: 'CVE-2020-28168' },
      { versions: '<0.21.2', severity: 'MEDIUM', description: 'Regular Expression Denial of Service', cve: 'CVE-2021-3749' }
    ],
    'express': [
      { versions: '<4.17.3', severity: 'MEDIUM', description: 'Open Redirect', cve: 'CVE-2022-24999' }
    ]
  };
  
  for (const [name, pkg] of Object.entries(dependencies)) {
    const vulnerablePkg = knownVulnerablePackages[name];
    if (vulnerablePkg) {
      for (const vuln of vulnerablePkg) {
        const version = pkg.version;
        if (version && semver.satisfies(version, vuln.versions)) {
          vulnerabilities.push({
            package: name,
            version: version,
            vulnerable_versions: vuln.versions,
            severity: vuln.severity,
            description: vuln.description,
            cve: vuln.cve,
            recommendation: `Update ${name} to a version outside the vulnerable range: ${vuln.versions}`
          });
        }
      }
    }
  }
  
  return vulnerabilities;
}

/**
 * Check for vulnerabilities in Python packages
 * @param {object} dependencies - Dependencies object
 * @param {object} options - Checking options
 * @returns {Promise<Array>} - List of vulnerabilities
 */
async function checkPythonPackageVulnerabilities(dependencies, options = {}) {
  // In a real implementation, this would call an actual vulnerability database API
  // For demo purposes, we'll check a few common packages with known issues
  
  const vulnerabilities = [];
  const knownVulnerablePackages = {
    'django': [
      { versions: '<3.2.12', severity: 'HIGH', description: 'SQL injection vulnerability', cve: 'CVE-2022-28347' },
      { versions: '<3.2.11', severity: 'MEDIUM', description: 'Potential directory traversal via Archive.extract', cve: 'CVE-2021-45452' }
    ],
    'flask': [
      { versions: '<2.0.1', severity: 'MEDIUM', description: 'URL parsing vulnerability', cve: 'CVE-2021-28091' }
    ],
    'requests': [
      { versions: '<2.26.0', severity: 'MEDIUM', description: 'Authorization header leak', cve: 'CVE-2021-34730' }
    ]
  };
  
  for (const [name, pkg] of Object.entries(dependencies)) {
    const vulnerablePkg = knownVulnerablePackages[name];
    if (vulnerablePkg) {
      for (const vuln of vulnerablePkg) {
        const version = pkg.version;
        if (version && semver.satisfies(version, vuln.versions)) {
          vulnerabilities.push({
            package: name,
            version: version,
            vulnerable_versions: vuln.versions,
            severity: vuln.severity,
            description: vuln.description,
            cve: vuln.cve,
            recommendation: `Update ${name} to a version outside the vulnerable range: ${vuln.versions}`
          });
        }
      }
    }
  }
  
  return vulnerabilities;
}

/**
 * Check for license issues in package dependencies
 * @param {object} dependencies - Dependencies object
 * @returns {Promise<Array>} - List of license issues
 */
async function checkLicenseIssues(dependencies) {
  const issues = [];
  const restrictedLicenses = ['GPL', 'AGPL', 'LGPL', 'UNLICENSED', 'UNKNOWN'];
  
  // In a real implementation, this would check a real license database
  // For demo purposes, we'll use some hardcoded license info
  const knownLicenses = {
    'react': 'MIT',
    'express': 'MIT',
    'lodash': 'MIT',
    'axios': 'MIT',
    'moment': 'MIT',
    'webpack': 'MIT',
    'babel': 'MIT',
    '@angular/core': 'MIT',
    'jquery': 'MIT'
  };
  
  for (const [name, pkg] of Object.entries(dependencies)) {
    const license = knownLicenses[name] || 'UNKNOWN';
    
    if (restrictedLicenses.some(restricted => license.includes(restricted))) {
      issues.push({
        package: name,
        license: license,
        severity: license === 'UNKNOWN' ? 'MEDIUM' : 'LOW',
        description: `Package ${name} uses a potentially restricted license: ${license}`,
        recommendation: `Review the license terms for ${name} to ensure compliance with your project's requirements`
      });
    }
  }
  
  return issues;
}

/**
 * Check for issues in package-lock.json
 * @param {string} filePath - Path to package-lock.json
 * @returns {Promise<Array>} - List of issues
 */
async function checkLockfileIssues(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const lockfile = JSON.parse(content);
    
    const issues = [];
    
    // Check lockfile version
    if (lockfile.lockfileVersion < 2) {
      issues.push({
        type: 'OUTDATED_LOCKFILE',
        severity: 'LOW',
        description: `Outdated lockfile version: ${lockfile.lockfileVersion}`,
        recommendation: 'Update to npm v7 or higher and regenerate the lockfile'
      });
    }
    
    // Check for integrity hashes
    const packages = lockfile.packages || {};
    let missingIntegrity = 0;
    
    for (const [pkgName, pkg] of Object.entries(packages)) {
      if (!pkg.integrity && pkgName !== '') {
        missingIntegrity++;
      }
    }
    
    if (missingIntegrity > 0) {
      issues.push({
        type: 'MISSING_INTEGRITY',
        severity: 'MEDIUM',
        description: `${missingIntegrity} packages are missing integrity hashes`,
        recommendation: 'Regenerate the lockfile with npm install'
      });
    }
    
    return issues;
  } catch (error) {
    console.error(chalk.red(`Error checking lockfile: ${error.message}`));
    return [{ 
      type: 'LOCKFILE_ERROR', 
      severity: 'MEDIUM',
      description: `Error parsing lockfile: ${error.message}`,
      recommendation: 'Regenerate the lockfile with npm install'
    }];
  }
}

/**
 * Find package files recursively in a directory
 * @param {string} dirPath - Path to directory
 * @returns {Promise<object>} - Object with file paths by type
 */
async function findPackageFiles(dirPath) {
  const result = {
    npm: [],
    python: []
  };
  
  await findPackageFilesRecursive(dirPath, result);
  
  return result;
}

/**
 * Recursively find package files
 * @param {string} dir - Directory to search
 * @param {object} result - Object to store results
 * @returns {Promise<void>}
 */
async function findPackageFilesRecursive(dir, result) {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      
      if (entry.isDirectory()) {
        // Skip node_modules and .git directories
        if (entry.name !== 'node_modules' && entry.name !== '.git') {
          await findPackageFilesRecursive(fullPath, result);
        }
      } else if (entry.isFile()) {
        // Categorize file by type
        if (entry.name === 'package.json') {
          result.npm.push(fullPath);
        } else if (entry.name === 'requirements.txt' || entry.name === 'Pipfile') {
          result.python.push(fullPath);
        }
      }
    }
  } catch (error) {
    console.warn(chalk.yellow(`Error reading directory ${dir}: ${error.message}`));
  }
}

/**
 * Main function for supply chain security scanning
 * @param {string} target - Target directory
 * @param {object} options - Scanning options
 * @returns {Promise<object>} - Scan results
 */
async function scanDependencies(target, options = {}) {
  try {
    const results = {
      target,
      timestamp: new Date().toISOString(),
      npmResults: { files: 0, vulnerabilities: 0 },
      pythonResults: { files: 0, vulnerabilities: 0 },
      allPackages: { total: 0, vulnerable: 0 }
    };
    
    const spinner = ora('Scanning dependencies...').start();
    
    // Find all package files
    const files = await findPackageFiles(target);
    
    // Analyze npm packages
    for (const file of files.npm) {
      const fileResult = await analyzeNodePackage(file, options);
      results.npmResults.files++;
      
      if (fileResult.vulnerabilities && fileResult.vulnerabilities.length > 0) {
        results.npmResults.vulnerabilities += fileResult.vulnerabilities.length;
        results.allPackages.vulnerable += fileResult.vulnerabilities.length;
        
        if (!results.npmResults.details) results.npmResults.details = [];
        results.npmResults.details.push({
          file,
          packageName: fileResult.packageName,
          vulnerabilities: fileResult.vulnerabilities,
          licenseIssues: fileResult.licenseIssues || [],
          lockfileIssues: fileResult.lockfileIssues || []
        });
      }
      
      // Track total packages
      if (fileResult.directDependencies) {
        results.allPackages.total += Object.keys(fileResult.directDependencies).length;
      }
    }
    
    // Analyze Python packages
    for (const file of files.python) {
      const fileResult = await analyzePythonRequirements(file, options);
      results.pythonResults.files++;
      
      if (fileResult.vulnerabilities && fileResult.vulnerabilities.length > 0) {
        results.pythonResults.vulnerabilities += fileResult.vulnerabilities.length;
        results.allPackages.vulnerable += fileResult.vulnerabilities.length;
        
        if (!results.pythonResults.details) results.pythonResults.details = [];
        results.pythonResults.details.push({
          file,
          vulnerabilities: fileResult.vulnerabilities
        });
      }
      
      // Track total packages
      if (fileResult.directDependencies) {
        results.allPackages.total += Object.keys(fileResult.directDependencies).length;
      }
    }
    
    spinner.succeed(`Scanned ${results.allPackages.total} dependencies (${results.npmResults.files} npm, ${results.pythonResults.files} Python)`);
    
    if (results.allPackages.vulnerable > 0) {
      console.log(chalk.red(`Found ${results.allPackages.vulnerable} vulnerabilities!`));
    } else {
      console.log(chalk.green('No vulnerabilities found in dependencies!'));
    }
    
    return results;
  } catch (error) {
    console.error(chalk.red(`Dependency scanning failed: ${error.message}`));
    throw error;
  }
}

module.exports = {
  scanDependencies,
  analyzeNodePackage,
  analyzePythonRequirements,
  checkPackageVulnerabilities
};
