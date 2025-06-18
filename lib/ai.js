/**
 * AI-powered Vulnerability Detection Module
 * This module uses AI to detect security vulnerabilities through code analysis and pattern recognition
 */

const fs = require('fs').promises;
const path = require('path');
const chalk = require('chalk');
const ora = require('ora');
const { OpenAI } = require('openai');
const { Tokenizer } = require('gpt-4-tokenizer');
const { wrapInTryCatch } = require('../utils/helpers');

// Initialize OpenAI client if API key is available
let openai;
try {
  if (process.env.OPENAI_API_KEY) {
    openai = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY
    });
  }
} catch (error) {
  console.warn(chalk.yellow('OpenAI client initialization failed. AI-powered analysis will not be available.'));
}

// Initialize tokenizer
const tokenizer = new Tokenizer();

/**
 * Vulnerability patterns that the AI model is trained to detect
 */
const VULNERABILITY_PATTERNS = {
  XSS: {
    description: 'Cross-Site Scripting (XSS)',
    patterns: ['innerHTML', 'document.write', 'eval(', 'dangerouslySetInnerHTML'],
    severity: 'HIGH'
  },
  SQLI: {
    description: 'SQL Injection',
    patterns: ['executeQuery', 'connection.query(', 'raw('],
    severity: 'CRITICAL'
  },
  OPEN_REDIRECT: {
    description: 'Open Redirect',
    patterns: ['redirect(', 'window.location'],
    severity: 'MEDIUM'
  },
  INSECURE_COOKIE: {
    description: 'Insecure Cookie',
    patterns: ['document.cookie', 'res.cookie(', 'Set-Cookie:'],
    severity: 'MEDIUM'
  },
  COMMAND_INJECTION: {
    description: 'Command Injection',
    patterns: ['exec(', 'spawn(', 'child_process'],
    severity: 'CRITICAL'
  },
  WEAK_CRYPTO: {
    description: 'Weak Cryptography',
    patterns: ['MD5', 'SHA1', 'createCipher('],
    severity: 'HIGH'
  },
  INSECURE_UPLOAD: {
    description: 'Insecure File Upload',
    patterns: ['multer', 'formidable', 'busboy'],
    severity: 'HIGH'
  },
  PROTOTYPE_POLLUTION: {
    description: 'Prototype Pollution',
    patterns: ['Object.assign(', 'extend(', 'merge('],
    severity: 'MEDIUM'
  }
};

/**
 * Analyze source code for potential vulnerabilities using AI
 * @param {string} sourceCode - Source code to analyze
 * @param {string} fileName - File name (for context)
 * @param {object} options - Analysis options
 * @returns {Promise<object>} - Analysis results
 */
async function analyzeSourceCodeWithAI(sourceCode, fileName, options = {}) {
  if (!openai) {
    return {
      success: false,
      error: 'OpenAI API key not configured',
      vulnerabilities: []
    };
  }

  try {
    // Determine file type
    const extension = path.extname(fileName).toLowerCase();
    const fileType = determineFileType(extension);
    
    // Truncate source code if too large
    const maxTokens = options.maxTokens || 4000;
    const encoded = tokenizer.encode(sourceCode);
    
    let codeSample = sourceCode;
    if (encoded.length > maxTokens) {
      codeSample = tokenizer.decode(encoded.slice(0, maxTokens));
      console.warn(chalk.yellow(`Source code truncated from ${encoded.length} to ${maxTokens} tokens`));
    }

    const prompt = `
      Analyze the following ${fileType} code for security vulnerabilities:
      
      File: ${fileName}
      
      \`\`\`${fileType}
      ${codeSample}
      \`\`\`
      
      Please identify any security vulnerabilities such as:
      - XSS (Cross-Site Scripting)
      - SQL Injection
      - Command Injection
      - Insecure Direct Object References
      - Broken Authentication
      - Sensitive Data Exposure
      - CSRF (Cross-Site Request Forgery)
      - Prototype Pollution
      - Insecure Deserialization
      - Any other security issues
      
      For each vulnerability, provide:
      1. The type of vulnerability
      2. The location in the code (line number if possible)
      3. Severity level (Low, Medium, High, Critical)
      4. A brief explanation of the issue
      5. A recommendation for fixing it
      
      Format your response as a JSON array with each item having these properties:
      {
        "type": "vulnerability type",
        "location": "line number or code snippet",
        "severity": "severity level",
        "description": "explanation of the issue",
        "recommendation": "how to fix it"
      }
      
      If no vulnerabilities are found, return an empty array.
    `;

    // Call OpenAI API
    const spinner = ora('Analyzing code with AI...').start();
    
    const response = await openai.chat.completions.create({
      model: "gpt-4-turbo",
      messages: [
        { role: "system", content: "You are an expert security auditor specialized in finding vulnerabilities in web application code. Your analysis should be thorough and focus only on real security issues." },
        { role: "user", content: prompt }
      ],
      response_format: { type: "json_object" }
    });
    
    spinner.succeed('AI code analysis complete');
    
    // Parse the JSON response
    const content = response.choices[0].message.content;
    const result = JSON.parse(content);
    
    return {
      success: true,
      fileName,
      fileType,
      tokenCount: encoded.length,
      vulnerabilities: result.vulnerabilities || []
    };
  } catch (error) {
    console.error(chalk.red(`AI analysis failed: ${error.message}`));
    return {
      success: false,
      error: error.message,
      vulnerabilities: []
    };
  }
}

/**
 * Analyze HTTP response for security issues using AI
 * @param {object} httpResponse - HTTP response object
 * @param {string} url - URL of the request
 * @param {object} options - Analysis options
 * @returns {Promise<object>} - Analysis results
 */
async function analyzeHttpResponseWithAI(httpResponse, url, options = {}) {
  if (!openai) {
    return {
      success: false,
      error: 'OpenAI API key not configured',
      issues: []
    };
  }

  try {
    // Extract relevant information from HTTP response
    const { status, headers, data } = httpResponse;
    
    // Prepare headers for analysis
    const headerString = Object.entries(headers)
      .map(([key, value]) => `${key}: ${value}`)
      .join('\n');
    
    // Prepare response body (truncate if needed)
    let bodyString = '';
    if (typeof data === 'string') {
      bodyString = data.slice(0, 1000); // Take first 1000 chars only
    } else if (data && typeof data === 'object') {
      bodyString = JSON.stringify(data, null, 2).slice(0, 1000);
    }
    
    const prompt = `
      Analyze the following HTTP response from ${url} for security issues:
      
      Status Code: ${status}
      
      Headers:
      ${headerString}
      
      Response Body (truncated):
      ${bodyString}
      
      Please identify any security issues such as:
      - Missing security headers
      - Information leakage
      - Sensitive data exposure
      - CORS misconfiguration
      - Authentication issues
      - Other security problems
      
      Format your response as a JSON array with each item having these properties:
      {
        "type": "issue type",
        "severity": "severity level",
        "description": "explanation of the issue",
        "recommendation": "how to fix it"
      }
      
      If no issues are found, return an empty array.
    `;

    // Call OpenAI API
    const spinner = ora('Analyzing HTTP response with AI...').start();
    
    const response = await openai.chat.completions.create({
      model: "gpt-4-turbo",
      messages: [
        { role: "system", content: "You are an expert security auditor specialized in analyzing HTTP responses for security issues. Focus only on finding real security problems." },
        { role: "user", content: prompt }
      ],
      response_format: { type: "json_object" }
    });
    
    spinner.succeed('AI HTTP response analysis complete');
    
    // Parse the JSON response
    const content = response.choices[0].message.content;
    const result = JSON.parse(content);
    
    return {
      success: true,
      url,
      statusCode: status,
      issues: result.issues || []
    };
  } catch (error) {
    console.error(chalk.red(`AI HTTP analysis failed: ${error.message}`));
    return {
      success: false,
      error: error.message,
      issues: []
    };
  }
}

/**
 * Determine file type from extension
 * @param {string} extension - File extension
 * @returns {string} - File type
 */
function determineFileType(extension) {
  const fileTypes = {
    '.js': 'javascript',
    '.ts': 'typescript',
    '.jsx': 'javascript',
    '.tsx': 'typescript',
    '.py': 'python',
    '.php': 'php',
    '.rb': 'ruby',
    '.java': 'java',
    '.go': 'go',
    '.cs': 'csharp',
    '.html': 'html',
    '.css': 'css',
    '.json': 'json'
  };

  return fileTypes[extension] || 'code';
}

/**
 * Analyze code for potential vulnerabilities using pattern matching
 * @param {string} sourceCode - Source code to analyze
 * @param {string} fileName - File name (for context)
 * @returns {Array} - Detected vulnerabilities
 */
function analyzeSourceCodeWithPatterns(sourceCode, fileName) {
  const vulnerabilities = [];
  
  // Check for each vulnerability pattern
  for (const [vulnType, vulnInfo] of Object.entries(VULNERABILITY_PATTERNS)) {
    const { patterns, description, severity } = vulnInfo;
    
    // Look for patterns in source code
    for (const pattern of patterns) {
      const regex = new RegExp(pattern, 'g');
      let match;
      
      while ((match = regex.exec(sourceCode)) !== null) {
        // Find line number
        const lineNumber = (sourceCode.substring(0, match.index).match(/\n/g) || []).length + 1;
        
        // Get context (the line where the pattern was found)
        const lines = sourceCode.split('\n');
        const contextLine = lines[lineNumber - 1];
        
        vulnerabilities.push({
          type: vulnType,
          description: description,
          severity: severity,
          location: `Line ${lineNumber}: ${contextLine.trim()}`,
          pattern: pattern,
          recommendation: generateRecommendation(vulnType, pattern)
        });
      }
    }
  }
  
  return vulnerabilities;
}

/**
 * Generate recommendation based on vulnerability type
 * @param {string} vulnType - Vulnerability type
 * @param {string} pattern - Pattern that was matched
 * @returns {string} - Recommendation
 */
function generateRecommendation(vulnType, pattern) {
  const recommendations = {
    XSS: `Sanitize user input before rendering. Use safer alternatives like textContent instead of ${pattern}.`,
    SQLI: `Use parameterized queries or ORM instead of ${pattern}.`,
    OPEN_REDIRECT: `Validate and sanitize URL parameters before using ${pattern}.`,
    INSECURE_COOKIE: `Use secure, httpOnly, and SameSite attributes when setting cookies.`,
    COMMAND_INJECTION: `Avoid using ${pattern} with user input. Use safer alternatives or strict input validation.`,
    WEAK_CRYPTO: `Use modern cryptographic algorithms like SHA-256 or HMAC instead of ${pattern}.`,
    INSECURE_UPLOAD: `Implement strict file validation and use proper file permissions.`,
    PROTOTYPE_POLLUTION: `Avoid using ${pattern} with untrusted data. Use Object.create(null) to create objects without prototype.`
  };
  
  return recommendations[vulnType] || 'Review this code for security implications.';
}

/**
 * Main function for AI-powered vulnerability detection
 * @param {string} target - Target URL, file, or directory
 * @param {object} options - Detection options
 * @returns {Promise<object>} - Detection results
 */
async function detectVulnerabilities(target, options = {}) {
  const results = {
    target,
    timestamp: new Date().toISOString(),
    useAI: !!openai,
    patternDetection: {
      files: 0,
      vulnerabilities: []
    },
    aiDetection: {
      files: 0,
      vulnerabilities: []
    }
  };
  
  try {
    // Check if target is a file or directory
    const stats = await fs.stat(target).catch(() => null);
    
    if (stats && stats.isFile()) {
      // Target is a file
      const sourceCode = await fs.readFile(target, 'utf-8');
      
      // Pattern-based detection
      const patternVulnerabilities = analyzeSourceCodeWithPatterns(sourceCode, target);
      results.patternDetection.files++;
      results.patternDetection.vulnerabilities.push(...patternVulnerabilities);
      
      // AI-based detection
      if (openai && options.useAI !== false) {
        const aiResults = await analyzeSourceCodeWithAI(sourceCode, target, options);
        if (aiResults.success) {
          results.aiDetection.files++;
          results.aiDetection.vulnerabilities.push(...aiResults.vulnerabilities);
        }
      }
    } else if (stats && stats.isDirectory()) {
      // Target is a directory, scan all files
      const files = await scanDirectory(target, options.extensions || ['.js', '.ts', '.jsx', '.tsx', '.php', '.py']);
      
      for (const file of files) {
        try {
          const sourceCode = await fs.readFile(file, 'utf-8');
          
          // Pattern-based detection
          const patternVulnerabilities = analyzeSourceCodeWithPatterns(sourceCode, file);
          results.patternDetection.files++;
          if (patternVulnerabilities.length > 0) {
            results.patternDetection.vulnerabilities.push({
              file,
              issues: patternVulnerabilities
            });
          }
          
          // AI-based detection (limit to fewer files)
          if (openai && options.useAI !== false && results.aiDetection.files < (options.maxAIFiles || 5)) {
            const aiResults = await analyzeSourceCodeWithAI(sourceCode, file, options);
            if (aiResults.success) {
              results.aiDetection.files++;
              if (aiResults.vulnerabilities.length > 0) {
                results.aiDetection.vulnerabilities.push({
                  file,
                  issues: aiResults.vulnerabilities
                });
              }
            }
          }
        } catch (error) {
          console.warn(chalk.yellow(`Error analyzing file ${file}: ${error.message}`));
        }
      }
    } else {
      // Target might be a URL or API
      if (target.startsWith('http')) {
        // Implement HTTP analysis here
        console.log(chalk.blue('Web application vulnerability detection not yet implemented'));
      } else {
        throw new Error('Target must be a valid file, directory, or URL');
      }
    }
    
    return results;
  } catch (error) {
    console.error(chalk.red(`Vulnerability detection failed: ${error.message}`));
    throw error;
  }
}

/**
 * Recursively scan a directory for files with specific extensions
 * @param {string} dir - Directory to scan
 * @param {Array} extensions - File extensions to include
 * @returns {Promise<Array>} - List of file paths
 */
async function scanDirectory(dir, extensions) {
  const files = [];
  
  // Read directory contents
  const entries = await fs.readdir(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
    if (entry.isDirectory()) {
      // Recursively scan subdirectory
      const subFiles = await scanDirectory(fullPath, extensions);
      files.push(...subFiles);
    } else if (entry.isFile()) {
      // Check file extension
      const ext = path.extname(entry.name).toLowerCase();
      if (extensions.includes(ext)) {
        files.push(fullPath);
      }
    }
  }
  
  return files;
}

module.exports = {
  detectVulnerabilities,
  analyzeSourceCodeWithPatterns,
  analyzeSourceCodeWithAI,
  analyzeHttpResponseWithAI,
  VULNERABILITY_PATTERNS
};
