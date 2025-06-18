/**
 * API Security Scanner Module
 * This module provides functionality to scan API endpoints for security vulnerabilities
 */

const axios = require('axios');
const chalk = require('chalk');
const ora = require('ora');
const swaggerParser = require('swagger-parser');
const fs = require('fs').promises;
const path = require('path');
const { checkAuthMethods } = require('./auth');

// Common API security issues
const API_SECURITY_ISSUES = {
  NO_AUTH: 'Endpoint has no authentication',
  WEAK_AUTH: 'Endpoint uses weak authentication mechanism',
  NO_RATE_LIMIT: 'No rate limiting detected',
  SENSITIVE_DATA_EXPOSURE: 'Endpoint may expose sensitive data',
  INSECURE_CORS: 'Insecure CORS configuration detected',
  NO_INPUT_VALIDATION: 'Insufficient input validation',
  EXCESSIVE_DATA_EXPOSURE: 'API returns more data than necessary',
  INSECURE_DIRECT_OBJECT_REFERENCES: 'Potential insecure direct object references',
  BROKEN_FUNCTION_LEVEL_AUTH: 'Potential broken function level authorization',
  MASS_ASSIGNMENT: 'Potential mass assignment vulnerability'
};

/**
 * Parse an OpenAPI/Swagger specification file and analyze security issues
 * @param {string} specPath - Path to OpenAPI/Swagger specification file
 * @returns {Promise<object>} - Analysis results
 */
async function analyzeApiSpec(specPath) {
  try {
    // Parse the API specification file
    const api = await swaggerParser.parse(specPath);
    const apiVersion = api.openapi || api.swagger;
    const isOpenApiV3 = apiVersion && apiVersion.startsWith('3.');
    
    const results = {
      specVersion: apiVersion,
      apiTitle: api.info?.title || 'Unknown API',
      apiVersion: api.info?.version || 'Unknown',
      securitySchemes: [],
      endpoints: [],
      securityIssues: [],
      securityScore: 100, // Start with perfect score and deduct for issues
    };
    
    // Analyze security schemes
    const securitySchemes = isOpenApiV3 
      ? (api.components?.securitySchemes || {}) 
      : (api.securityDefinitions || {});
    
    for (const [name, scheme] of Object.entries(securitySchemes)) {
      results.securitySchemes.push({
        name,
        type: scheme.type,
        strength: analyzeAuthStrength(scheme),
      });
    }
    
    // Check for global security requirements
    const globalSecurityRequirements = api.security || [];
    const hasGlobalSecurity = globalSecurityRequirements.length > 0;
    
    // Analyze endpoints
    const paths = api.paths || {};
    for (const [path, methods] of Object.entries(paths)) {
      for (const [method, operation] of Object.entries(methods)) {
        if (['get', 'post', 'put', 'delete', 'patch'].includes(method)) {
          const endpointSecurity = analyzeEndpointSecurity(path, method, operation, hasGlobalSecurity, securitySchemes);
          results.endpoints.push(endpointSecurity);
          
          // Add security issues to overall results
          results.securityIssues.push(...endpointSecurity.issues);
          
          // Deduct from security score for each issue
          results.securityScore -= endpointSecurity.issues.length * 5;
        }
      }
    }
    
    // Ensure score doesn't go below 0
    results.securityScore = Math.max(0, results.securityScore);
    
    return results;
  } catch (error) {
    console.error(chalk.red(`Error analyzing API spec: ${error.message}`));
    throw error;
  }
}

/**
 * Analyze the security of an API endpoint
 * @param {string} path - API path
 * @param {string} method - HTTP method
 * @param {object} operation - Operation object from OpenAPI spec
 * @param {boolean} hasGlobalSecurity - Whether the API has global security requirements
 * @param {object} securitySchemes - Security schemes defined in the spec
 * @returns {object} - Endpoint security analysis
 */
function analyzeEndpointSecurity(path, method, operation, hasGlobalSecurity, securitySchemes) {
  const endpointSecurity = {
    path,
    method: method.toUpperCase(),
    description: operation.summary || operation.description || 'No description',
    hasAuth: false,
    authMethods: [],
    hasRateLimiting: false,
    inputValidation: false,
    issues: []
  };
  
  // Check if endpoint has security requirements
  const securityReqs = operation.security || [];
  endpointSecurity.hasAuth = securityReqs.length > 0 || hasGlobalSecurity;
  
  if (!endpointSecurity.hasAuth) {
    // Check if it's a public endpoint by design
    const isPublicByDesign = operation.tags?.includes('public') || 
                             path.includes('/public/') || 
                             path.endsWith('/login') || 
                             path.endsWith('/register');
    
    if (!isPublicByDesign) {
      endpointSecurity.issues.push({
        type: API_SECURITY_ISSUES.NO_AUTH,
        severity: 'HIGH',
        description: `Endpoint ${method.toUpperCase()} ${path} has no authentication requirements`
      });
    }
  } else {
    // Analyze auth methods
    securityReqs.forEach(req => {
      const schemes = Object.keys(req);
      schemes.forEach(scheme => {
        if (securitySchemes[scheme]) {
          const authStrength = analyzeAuthStrength(securitySchemes[scheme]);
          endpointSecurity.authMethods.push({
            scheme: scheme,
            type: securitySchemes[scheme].type,
            strength: authStrength
          });
          
          if (authStrength === 'weak') {
            endpointSecurity.issues.push({
              type: API_SECURITY_ISSUES.WEAK_AUTH,
              severity: 'MEDIUM',
              description: `Endpoint uses weak authentication scheme: ${scheme}`
            });
          }
        }
      });
    });
  }
  
  // Check for input validation
  endpointSecurity.inputValidation = checkInputValidation(operation);
  if (!endpointSecurity.inputValidation) {
    endpointSecurity.issues.push({
      type: API_SECURITY_ISSUES.NO_INPUT_VALIDATION,
      severity: 'MEDIUM',
      description: `Endpoint ${method.toUpperCase()} ${path} has insufficient input validation`
    });
  }
  
  // Check for sensitive data exposure
  if (method.toLowerCase() === 'get' && containsSensitiveDataPattern(path)) {
    endpointSecurity.issues.push({
      type: API_SECURITY_ISSUES.SENSITIVE_DATA_EXPOSURE,
      severity: 'HIGH',
      description: `Endpoint may expose sensitive data: ${path}`
    });
  }
  
  // Check for rate limiting
  endpointSecurity.hasRateLimiting = checkForRateLimiting(operation);
  if (!endpointSecurity.hasRateLimiting && method.toLowerCase() !== 'get') {
    endpointSecurity.issues.push({
      type: API_SECURITY_ISSUES.NO_RATE_LIMIT,
      severity: 'MEDIUM',
      description: `No rate limiting detected for ${method.toUpperCase()} ${path}`
    });
  }
  
  return endpointSecurity;
}

/**
 * Check if an operation has input validation
 * @param {object} operation - Operation object from OpenAPI spec
 * @returns {boolean} - Whether the operation has input validation
 */
function checkInputValidation(operation) {
  // Check if the operation has parameters or requestBody with schema
  const hasParameters = operation.parameters && operation.parameters.length > 0;
  const hasRequestBodySchema = operation.requestBody?.content?.['application/json']?.schema;
  
  if (hasParameters) {
    // Check if parameters have schemas
    const parametersWithSchema = operation.parameters.filter(param => param.schema);
    return parametersWithSchema.length > 0;
  }
  
  return !!hasRequestBodySchema;
}

/**
 * Analyze the strength of an authentication scheme
 * @param {object} scheme - Security scheme object from OpenAPI spec
 * @returns {string} - 'strong', 'medium', or 'weak'
 */
function analyzeAuthStrength(scheme) {
  const { type, scheme: schemeType } = scheme;
  
  if (type === 'oauth2' || type === 'openIdConnect') {
    return 'strong';
  } else if (type === 'http') {
    if (schemeType === 'bearer') return 'medium';
    if (schemeType === 'basic') return 'weak';
    return 'medium';
  } else if (type === 'apiKey') {
    return 'medium';
  }
  
  return 'weak';
}

/**
 * Check if a path potentially contains sensitive data
 * @param {string} path - API path
 * @returns {boolean} - Whether the path potentially contains sensitive data
 */
function containsSensitiveDataPattern(path) {
  const sensitivePatterns = [
    'user', 'account', 'profile', 'admin', 'password', 
    'credential', 'token', 'secret', 'key', 'auth', 
    'credit', 'payment', 'card', 'ssn', 'social', 'secure'
  ];
  
  const lowerPath = path.toLowerCase();
  return sensitivePatterns.some(pattern => lowerPath.includes(pattern));
}

/**
 * Check if an operation has rate limiting
 * @param {object} operation - Operation object from OpenAPI spec
 * @returns {boolean} - Whether the operation has rate limiting
 */
function checkForRateLimiting(operation) {
  // Check for rate limiting headers in responses
  const hasRateLimitHeaders = Object.values(operation.responses || {}).some(response => {
    const headers = response.headers || {};
    return Object.keys(headers).some(header => 
      header.toLowerCase().includes('rate-limit') || 
      header.toLowerCase().includes('ratelimit')
    );
  });
  
  // Check for rate limiting extensions
  const hasRateLimitExtension = operation['x-rate-limit'] || operation['x-ratelimit-limit'];
  
  return hasRateLimitHeaders || hasRateLimitExtension;
}

/**
 * Perform active API security testing by sending requests to endpoints
 * @param {string} baseUrl - Base URL of the API
 * @param {Array} endpoints - List of endpoints to test
 * @param {object} options - Testing options
 * @returns {Promise<object>} - Testing results
 */
async function activeApiTesting(baseUrl, endpoints, options = {}) {
  const results = {
    testedEndpoints: 0,
    vulnerabilities: [],
    timestamp: new Date().toISOString()
  };
  
  const spinner = ora('Performing active API testing...').start();
  
  try {
    for (const endpoint of endpoints) {
      const { path, method } = endpoint;
      const url = new URL(path, baseUrl).toString();
      
      // Test for lack of authentication
      if (endpoint.hasAuth) {
        try {
          const response = await axios({
            method: method.toLowerCase(),
            url,
            timeout: options.timeout || 5000,
            validateStatus: () => true
          });
          
          // If successful response without auth, potential issue
          if (response.status < 400) {
            results.vulnerabilities.push({
              type: API_SECURITY_ISSUES.BROKEN_FUNCTION_LEVEL_AUTH,
              severity: 'HIGH',
              endpoint: `${method} ${path}`,
              details: `Endpoint accessible without authentication. Status: ${response.status}`
            });
          }
        } catch (error) {
          // Network error, timeout, etc.
        }
      }
      
      // Test for CORS misconfiguration
      try {
        const corsResponse = await axios({
          method: 'OPTIONS',
          url,
          headers: {
            'Origin': 'https://malicious-site.com',
            'Access-Control-Request-Method': method
          },
          timeout: options.timeout || 5000,
          validateStatus: () => true
        });
        
        const allowOrigin = corsResponse.headers['access-control-allow-origin'];
        if (allowOrigin === '*' || allowOrigin === 'https://malicious-site.com') {
          results.vulnerabilities.push({
            type: API_SECURITY_ISSUES.INSECURE_CORS,
            severity: 'MEDIUM',
            endpoint: `${method} ${path}`,
            details: `Insecure CORS configuration. Allow-Origin: ${allowOrigin}`
          });
        }
      } catch (error) {
        // Network error, timeout, etc.
      }
      
      results.testedEndpoints++;
    }
    
    spinner.succeed(`Tested ${results.testedEndpoints} API endpoints`);
    return results;
  } catch (error) {
    spinner.fail(`API testing failed: ${error.message}`);
    throw error;
  }
}

/**
 * Discover API endpoints by crawling a website
 * @param {string} targetUrl - URL to crawl
 * @returns {Promise<Array>} - Discovered API endpoints
 */
async function discoverApiEndpoints(targetUrl) {
  // Implementation for API endpoint discovery
  // This would use Puppeteer to crawl a website and look for API calls
  // For now, we'll return a placeholder
  return [
    { path: '/api/users', method: 'GET' },
    { path: '/api/auth/login', method: 'POST' },
    { path: '/api/products', method: 'GET' }
  ];
}

/**
 * Main function for API security scanning
 * @param {string} target - Target URL or API spec file
 * @param {object} options - Scanning options
 * @returns {Promise<object>} - Scan results
 */
async function scanApi(target, options = {}) {
  try {
    let results = {
      target,
      timestamp: new Date().toISOString(),
      apiSpec: null,
      activeTesting: null,
      discovery: null,
      overallScore: 0
    };
    
    // Determine if target is a URL or a file
    const isUrl = target.startsWith('http://') || target.startsWith('https://');
    
    if (!isUrl && await fileExists(target)) {
      // Target is an API spec file
      const spinner = ora('Analyzing API specification...').start();
      results.apiSpec = await analyzeApiSpec(target);
      spinner.succeed('API specification analyzed');
      
      // If a base URL is provided, perform active testing
      if (options.baseUrl) {
        results.activeTesting = await activeApiTesting(
          options.baseUrl,
          results.apiSpec.endpoints,
          options
        );
      }
    } else if (isUrl) {
      // Target is a URL, try to discover API endpoints
      const spinner = ora('Discovering API endpoints...').start();
      results.discovery = await discoverApiEndpoints(target);
      spinner.succeed(`Discovered ${results.discovery.length} API endpoints`);
      
      // Perform active testing on discovered endpoints
      results.activeTesting = await activeApiTesting(
        target,
        results.discovery,
        options
      );
    } else {
      throw new Error('Target must be a valid URL or an API specification file');
    }
    
    // Calculate overall score
    if (results.apiSpec) {
      results.overallScore = results.apiSpec.securityScore;
    } else if (results.activeTesting) {
      // Calculate score based on vulnerabilities found
      const vulnerabilityCount = results.activeTesting.vulnerabilities.length;
      const testedEndpoints = results.activeTesting.testedEndpoints;
      
      if (testedEndpoints > 0) {
        results.overallScore = Math.max(0, 100 - (vulnerabilityCount / testedEndpoints * 100));
      }
    }
    
    return results;
  } catch (error) {
    console.error(chalk.red(`API security scan failed: ${error.message}`));
    throw error;
  }
}

/**
 * Check if a file exists
 * @param {string} filePath - Path to file
 * @returns {Promise<boolean>} - Whether the file exists
 */
async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

module.exports = {
  scanApi,
  analyzeApiSpec,
  activeApiTesting,
  discoverApiEndpoints,
  API_SECURITY_ISSUES
};
