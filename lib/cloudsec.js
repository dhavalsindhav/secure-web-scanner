/**
 * Cloud Security Scanner Module
 * This module provides functionality to scan cloud resources for security vulnerabilities
 */

const axios = require('axios');
const chalk = require('chalk');
const ora = require('ora');
const yaml = require('js-yaml');
const fs = require('fs').promises;
const path = require('path');

/**
 * Common cloud security issues
 */
const CLOUD_SECURITY_ISSUES = {
  PUBLIC_S3_BUCKET: 'Public S3 bucket detected',
  PUBLIC_STORAGE_BLOB: 'Public cloud storage blob detected', 
  OPEN_SECURITY_GROUP: 'Overly permissive security group detected',
  INSECURE_IAM_POLICY: 'Insecure IAM policy detected',
  UNENCRYPTED_DATA: 'Unencrypted data at rest detected',
  DEFAULT_VPC_USAGE: 'Default VPC in use',
  INSECURE_API_GATEWAY: 'Insecure API Gateway configuration detected',
  ROOT_ACCOUNT_USAGE: 'Root account usage detected',
  INSECURE_LAMBDA_FUNCTION: 'Lambda function with excessive permissions detected',
  INSECURE_CLOUD_FORMATION: 'Insecure CloudFormation template detected',
  INSECURE_TERRAFORM: 'Insecure Terraform configuration detected',
  INSECURE_KUBERNETES: 'Insecure Kubernetes configuration detected'
};

/**
 * Cloud providers
 */
const CLOUD_PROVIDERS = {
  AWS: 'amazon-web-services',
  AZURE: 'microsoft-azure', 
  GCP: 'google-cloud-platform',
  DO: 'digital-ocean',
  ALICLOUD: 'alibaba-cloud',
  IBM: 'ibm-cloud'
};

/**
 * Analyze Terraform file for security issues
 * @param {string} filePath - Path to Terraform file
 * @returns {Promise<object>} - Analysis results
 */
async function analyzeTerraformFile(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    
    // Parse HCL content (simplified, in a real implementation 
    // you would use a proper HCL parser)
    const result = {
      file: filePath,
      issues: [],
      resources: []
    };
    
    // Simple pattern matching for common security issues
    if (content.includes('acl = "public-read"')) {
      result.issues.push({
        type: CLOUD_SECURITY_ISSUES.PUBLIC_S3_BUCKET,
        severity: 'HIGH',
        description: 'Public S3 bucket detected with acl = "public-read"',
        recommendation: 'Set acl to "private" for S3 buckets unless public access is required.'
      });
    }
    
    if (content.includes('cidr_blocks = ["0.0.0.0/0"]') && content.includes('security_group')) {
      result.issues.push({
        type: CLOUD_SECURITY_ISSUES.OPEN_SECURITY_GROUP,
        severity: 'HIGH',
        description: 'Security group allows access from any IP address (0.0.0.0/0)',
        recommendation: 'Restrict security group rules to specific IP ranges.'
      });
    }
    
    if (content.includes('encrypt') && content.includes('false')) {
      result.issues.push({
        type: CLOUD_SECURITY_ISSUES.UNENCRYPTED_DATA,
        severity: 'MEDIUM',
        description: 'Resource with encryption disabled detected',
        recommendation: 'Enable encryption for sensitive data at rest.'
      });
    }
    
    return result;
  } catch (error) {
    console.error(chalk.red(`Error analyzing Terraform file: ${error.message}`));
    return { file: filePath, issues: [], resources: [], error: error.message };
  }
}

/**
 * Analyze CloudFormation template for security issues
 * @param {string} filePath - Path to CloudFormation template
 * @returns {Promise<object>} - Analysis results
 */
async function analyzeCloudFormationTemplate(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    let template;
    
    // Parse template based on file extension
    if (filePath.endsWith('.json')) {
      template = JSON.parse(content);
    } else if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
      template = yaml.load(content);
    } else {
      throw new Error('Unsupported file format. Only JSON and YAML are supported.');
    }
    
    const result = {
      file: filePath,
      issues: [],
      resources: []
    };
    
    // Extract resources
    const resources = template.Resources || {};
    
    // Track resources for reporting
    for (const [id, resource] of Object.entries(resources)) {
      result.resources.push({
        id,
        type: resource.Type,
        properties: resource.Properties ? Object.keys(resource.Properties) : []
      });
    }
    
    // Check for S3 buckets with public access
    for (const [id, resource] of Object.entries(resources)) {
      if (resource.Type === 'AWS::S3::Bucket') {
        const properties = resource.Properties || {};
        
        // Check for public access configurations
        if (properties.AccessControl === 'PublicRead' || properties.AccessControl === 'PublicReadWrite') {
          result.issues.push({
            type: CLOUD_SECURITY_ISSUES.PUBLIC_S3_BUCKET,
            resource: id,
            severity: 'HIGH',
            description: `S3 bucket ${id} has public access control: ${properties.AccessControl}`,
            recommendation: 'Set AccessControl to Private unless public access is required.'
          });
        }
        
        // Check for encryption
        if (!properties.BucketEncryption) {
          result.issues.push({
            type: CLOUD_SECURITY_ISSUES.UNENCRYPTED_DATA,
            resource: id,
            severity: 'MEDIUM',
            description: `S3 bucket ${id} does not have encryption configured`,
            recommendation: 'Enable server-side encryption for S3 buckets.'
          });
        }
      }
      
      // Check for security groups with open ingress
      if (resource.Type === 'AWS::EC2::SecurityGroup') {
        const properties = resource.Properties || {};
        const ingress = properties.SecurityGroupIngress || [];
        
        for (const rule of ingress) {
          if (rule.CidrIp === '0.0.0.0/0' && (rule.FromPort === 22 || rule.FromPort === 3389)) {
            result.issues.push({
              type: CLOUD_SECURITY_ISSUES.OPEN_SECURITY_GROUP,
              resource: id,
              severity: 'HIGH',
              description: `Security group ${id} allows ${rule.FromPort === 22 ? 'SSH' : 'RDP'} access from any IP address`,
              recommendation: 'Restrict SSH/RDP access to specific IP addresses.'
            });
          }
        }
      }
      
      // Check for IAM policies with wildcard actions
      if (resource.Type === 'AWS::IAM::Policy' || resource.Type === 'AWS::IAM::Role') {
        const properties = resource.Properties || {};
        const policyDocument = properties.PolicyDocument || {};
        const statements = policyDocument.Statement || [];
        
        for (const statement of Array.isArray(statements) ? statements : [statements]) {
          const action = statement.Action;
          const actions = Array.isArray(action) ? action : [action];
          
          if (actions.includes('*') && statement.Effect === 'Allow') {
            result.issues.push({
              type: CLOUD_SECURITY_ISSUES.INSECURE_IAM_POLICY,
              resource: id,
              severity: 'HIGH',
              description: `IAM policy ${id} allows wildcard (*) actions`,
              recommendation: 'Specify only the required actions in IAM policies instead of using wildcards.'
            });
          }
        }
      }
    }
    
    return result;
  } catch (error) {
    console.error(chalk.red(`Error analyzing CloudFormation template: ${error.message}`));
    return { file: filePath, issues: [], resources: [], error: error.message };
  }
}

/**
 * Analyze Kubernetes manifest for security issues
 * @param {string} filePath - Path to Kubernetes manifest
 * @returns {Promise<object>} - Analysis results
 */
async function analyzeKubernetesManifest(filePath) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    let manifest;
    
    // Parse manifest
    manifest = yaml.load(content);
    
    const result = {
      file: filePath,
      issues: [],
      resources: []
    };
    
    // Track resource for reporting
    const kind = manifest.kind;
    const name = manifest.metadata?.name;
    result.resources.push({ kind, name });
    
    // Check for privileged containers
    if (kind === 'Pod' || kind === 'Deployment' || kind === 'StatefulSet' || kind === 'DaemonSet') {
      const containers = manifest.spec?.template?.spec?.containers || manifest.spec?.containers || [];
      
      for (const container of containers) {
        // Check for privileged security context
        if (container.securityContext?.privileged === true) {
          result.issues.push({
            type: CLOUD_SECURITY_ISSUES.INSECURE_KUBERNETES,
            resource: `${kind}/${name}`,
            severity: 'HIGH',
            description: `Container ${container.name} is running in privileged mode`,
            recommendation: 'Avoid using privileged containers. Use more restrictive security contexts.'
          });
        }
        
        // Check for hostNetwork
        if (manifest.spec?.hostNetwork === true || manifest.spec?.template?.spec?.hostNetwork === true) {
          result.issues.push({
            type: CLOUD_SECURITY_ISSUES.INSECURE_KUBERNETES,
            resource: `${kind}/${name}`,
            severity: 'MEDIUM',
            description: `${kind} ${name} is using host network`,
            recommendation: 'Avoid using host network unless absolutely necessary.'
          });
        }
        
        // Check for capabilities
        const capabilities = container.securityContext?.capabilities?.add || [];
        if (capabilities.includes('ALL') || capabilities.includes('SYS_ADMIN')) {
          result.issues.push({
            type: CLOUD_SECURITY_ISSUES.INSECURE_KUBERNETES,
            resource: `${kind}/${name}`,
            severity: 'HIGH',
            description: `Container ${container.name} has dangerous capabilities: ${capabilities.join(', ')}`,
            recommendation: 'Avoid adding unnecessary capabilities, especially ALL or SYS_ADMIN.'
          });
        }
      }
    }
    
    // Check for RBAC with wildcard permissions
    if (kind === 'Role' || kind === 'ClusterRole') {
      const rules = manifest.rules || [];
      
      for (const rule of rules) {
        const resources = rule.resources || [];
        const verbs = rule.verbs || [];
        
        if ((resources.includes('*') || verbs.includes('*')) && kind === 'ClusterRole') {
          result.issues.push({
            type: CLOUD_SECURITY_ISSUES.INSECURE_KUBERNETES,
            resource: `${kind}/${name}`,
            severity: 'HIGH',
            description: `${kind} ${name} has wildcard permissions: resources=${resources.join(',')}, verbs=${verbs.join(',')}`,
            recommendation: 'Avoid using wildcard permissions in RBAC. Specify only the required resources and verbs.'
          });
        }
      }
    }
    
    return result;
  } catch (error) {
    console.error(chalk.red(`Error analyzing Kubernetes manifest: ${error.message}`));
    return { file: filePath, issues: [], resources: [], error: error.message };
  }
}

/**
 * Analyze cloud configuration files in a directory
 * @param {string} dirPath - Path to directory
 * @param {object} options - Analysis options
 * @returns {Promise<object>} - Analysis results
 */
async function analyzeCloudConfig(dirPath, options = {}) {
  try {
    const results = {
      dir: dirPath,
      timestamp: new Date().toISOString(),
      terraformResults: { files: 0, issues: [] },
      cloudFormationResults: { files: 0, issues: [] },
      kubernetesResults: { files: 0, issues: [] }
    };
    
    const spinner = ora('Scanning cloud configuration files...').start();
    
    // Find all relevant files
    const files = await findCloudConfigFiles(dirPath);
    
    // Analyze Terraform files
    for (const file of files.terraform) {
      const fileResult = await analyzeTerraformFile(file);
      results.terraformResults.files++;
      
      if (fileResult.issues.length > 0) {
        results.terraformResults.issues.push({
          file,
          issues: fileResult.issues
        });
      }
    }
    
    // Analyze CloudFormation templates
    for (const file of files.cloudFormation) {
      const fileResult = await analyzeCloudFormationTemplate(file);
      results.cloudFormationResults.files++;
      
      if (fileResult.issues.length > 0) {
        results.cloudFormationResults.issues.push({
          file,
          issues: fileResult.issues
        });
      }
    }
    
    // Analyze Kubernetes manifests
    for (const file of files.kubernetes) {
      const fileResult = await analyzeKubernetesManifest(file);
      results.kubernetesResults.files++;
      
      if (fileResult.issues.length > 0) {
        results.kubernetesResults.issues.push({
          file,
          issues: fileResult.issues
        });
      }
    }
    
    spinner.succeed(`Scanned ${results.terraformResults.files + results.cloudFormationResults.files + results.kubernetesResults.files} cloud configuration files`);
    
    return results;
  } catch (error) {
    console.error(chalk.red(`Cloud config analysis failed: ${error.message}`));
    throw error;
  }
}

/**
 * Find cloud configuration files in a directory
 * @param {string} dirPath - Path to directory
 * @returns {Promise<object>} - Object containing file paths by type
 */
async function findCloudConfigFiles(dirPath) {
  const result = {
    terraform: [],
    cloudFormation: [],
    kubernetes: []
  };
  
  // Recursively find files
  await findFiles(dirPath, result);
  
  return result;
}

/**
 * Recursively find files in a directory
 * @param {string} dir - Directory to search
 * @param {object} result - Object to store results
 * @returns {Promise<void>}
 */
async function findFiles(dir, result) {
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      
      if (entry.isDirectory()) {
        // Skip node_modules and .git directories
        if (entry.name !== 'node_modules' && entry.name !== '.git') {
          await findFiles(fullPath, result);
        }
      } else if (entry.isFile()) {
        // Categorize file by type
        if (entry.name.endsWith('.tf')) {
          result.terraform.push(fullPath);
        } else if (entry.name.endsWith('.template') || 
                entry.name.endsWith('.json') || 
                entry.name.endsWith('.yaml') || 
                entry.name.endsWith('.yml')) {
          
          // Determine if it's CloudFormation or Kubernetes
          const content = await fs.readFile(fullPath, 'utf-8');
          
          if (content.includes('AWSTemplateFormatVersion') || 
              content.includes('Resources') && content.includes('Type": "AWS::')) {
            result.cloudFormation.push(fullPath);
          } else if (content.includes('apiVersion') && content.includes('kind')) {
            result.kubernetes.push(fullPath);
          }
        }
      }
    }
  } catch (error) {
    console.warn(chalk.yellow(`Error reading directory ${dir}: ${error.message}`));
  }
}

/**
 * Scan cloud provider API for security issues (if credentials are available)
 * @param {string} provider - Cloud provider (AWS, Azure, GCP)
 * @param {object} options - Scanning options
 * @returns {Promise<object>} - Scan results
 */
async function scanCloudProvider(provider, options = {}) {
  const spinner = ora(`Scanning ${provider} resources...`).start();
  
  try {
    // Placeholder for actual cloud provider API calls
    // In a real implementation, this would use the respective cloud provider SDKs
    
    const results = {
      provider,
      timestamp: new Date().toISOString(),
      resources: [],
      issues: []
    };
    
    spinner.succeed(`${provider} resources scanned`);
    return results;
  } catch (error) {
    spinner.fail(`${provider} scan failed: ${error.message}`);
    throw error;
  }
}

/**
 * Main function for cloud security scanning
 * @param {string} target - Target directory or cloud provider
 * @param {object} options - Scanning options
 * @returns {Promise<object>} - Scan results
 */
async function scanCloud(target, options = {}) {
  try {
    let results = {
      target,
      timestamp: new Date().toISOString()
    };
    
    // Determine if target is a directory or cloud provider
    if (Object.values(CLOUD_PROVIDERS).includes(target.toLowerCase())) {
      // Target is a cloud provider
      results = await scanCloudProvider(target, options);
    } else {
      // Target is a directory
      const stats = await fs.stat(target).catch(() => null);
      
      if (stats && stats.isDirectory()) {
        results = await analyzeCloudConfig(target, options);
      } else {
        throw new Error('Target must be a valid directory or cloud provider name');
      }
    }
    
    return results;
  } catch (error) {
    console.error(chalk.red(`Cloud security scan failed: ${error.message}`));
    throw error;
  }
}

module.exports = {
  scanCloud,
  analyzeCloudConfig,
  analyzeTerraformFile,
  analyzeCloudFormationTemplate,
  analyzeKubernetesManifest,
  CLOUD_SECURITY_ISSUES,
  CLOUD_PROVIDERS
};
