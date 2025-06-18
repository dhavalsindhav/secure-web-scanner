/**
 * This module provides compatibility helpers for browser environments
 * It helps detect the environment and provides mock implementations for Node-only modules
 */

// Check if we're running in a browser environment
const isBrowser = typeof window !== 'undefined' && typeof window.document !== 'undefined';
const isNode = typeof process !== 'undefined' && process.versions && process.versions.node;

/**
 * Safe require function that returns a mock object if module is not available
 * @param {string} moduleName - Module name to require
 * @param {object} mockImplementation - Optional mock implementation for browser
 * @returns {any} - The required module or mock implementation
 */
function safeRequire(moduleName, mockImplementation = {}) {
  if (isBrowser) {
    console.warn(`[secure-web-scanner] Browser environment detected. Module '${moduleName}' is not available.`);
    return mockImplementation;
  }
  
  try {
    return require(moduleName);
  } catch (error) {
    console.warn(`[secure-web-scanner] Could not load module '${moduleName}'. Using mock implementation.`, error);
    return mockImplementation;
  }
}

/**
 * Creates a proxy function that warns when a Node-only feature is used in browser
 * @param {string} featureName - Name of the feature
 * @returns {Function} - A function that warns when called
 */
function createUnavailableFeatureProxy(featureName) {
  return new Proxy(() => {}, {
    apply: function(target, thisArg, args) {
      console.warn(`[secure-web-scanner] '${featureName}' is not available in browser environments.`);
      return Promise.resolve({ 
        error: `Feature '${featureName}' is not available in browser environments`,
        browserCompatible: false 
      });
    },
    get: function(target, prop) {
      if (prop === 'then' || prop === 'catch' || prop === 'finally') {
        return undefined; // Make it not thenable
      }
      return createUnavailableFeatureProxy(`${featureName}.${String(prop)}`);
    }
  });
}

module.exports = {
  isBrowser,
  isNode,
  safeRequire,
  createUnavailableFeatureProxy
};
