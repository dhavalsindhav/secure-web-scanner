const path = require('path');

module.exports = {
  mode: 'production',
  entry: './browser-bundle.js',
  output: {
    filename: 'secure-web-scanner.browser.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'secureWebScanner',
    libraryTarget: 'umd',
    globalObject: 'this',
  },
  target: 'web',
  node: {
    // Prevent webpack from injecting Node polyfills
    global: true,
    __filename: false,
    __dirname: false,
  },
  resolve: {
    fallback: {
      // Provide empty mocks for Node.js core modules
      fs: false,
      path: require.resolve('path-browserify'),
      crypto: require.resolve('crypto-browserify'),
      stream: require.resolve('stream-browserify'),
      util: require.resolve('util/'),
      buffer: require.resolve('buffer/'),
      events: require.resolve('events/'),
      assert: require.resolve('assert/'),
      process: require.resolve('process/browser'),
    }
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', { targets: 'defaults' }]
            ]
          }
        }
      }
    ]
  },
  externals: {
    // Mark these Node.js modules as external
    'puppeteer': 'puppeteer',
    'whois-json': 'whois-json',
    'node-port-scanner': 'node-port-scanner',
    'swagger-parser': 'swagger-parser',
    'js-yaml': 'js-yaml',
    'openai': 'openai',
    'gpt-4-tokenizer': 'gpt-4-tokenizer',
    // Add any other problematic Node.js-only modules here
  }
};
