/**
 * Reporting module tests
 */
const { generateReport, serveDashboard } = require('../lib/reporting');
const fs = require('fs');
const path = require('path');

jest.mock('fs', () => ({
  promises: {
    writeFile: jest.fn().mockResolvedValue(undefined),
    mkdir: jest.fn().mockResolvedValue(undefined),
    access: jest.fn().mockRejectedValue(new Error('File not exists'))
  },
  existsSync: jest.fn().mockReturnValue(false)
}));

jest.mock('express', () => {
  const mockApp = {
    use: jest.fn(),
    get: jest.fn(),
    listen: jest.fn().mockImplementation((port, callback) => {
      if (callback) callback();
      return {
        address: jest.fn().mockReturnValue({ port: 3000 })
      };
    }),
    set: jest.fn()
  };
  return jest.fn().mockReturnValue(mockApp);
});

jest.mock('socket.io', () => {
  return {
    Server: jest.fn().mockImplementation(() => {
      return {
        on: jest.fn()
      };
    })
  };
});

describe('Reporting Module Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });
  
  test('generateReport should create reports in specified formats', async () => {
    const scanResults = {
      target: 'example.com',
      timestamp: new Date().toISOString(),
      ssl: { grade: 'A' },
      headers: { security: { 'Content-Security-Policy': { enabled: true } } }
    };
    
    const options = {
      formats: ['json', 'html'],
      outputPath: './test-report'
    };
    
    const result = await generateReport(scanResults, options);
    
    expect(result).toBeDefined();
    expect(result.reports).toBeDefined();
    expect(result.reports.length).toBe(2);
    expect(fs.promises.writeFile).toHaveBeenCalledTimes(2);
  });
  
  test('serveDashboard should start a server and return URL', async () => {
    const result = await serveDashboard({
      target: 'example.com',
      timestamp: new Date().toISOString()
    }, { port: 3000 });
    
    expect(result).toBeDefined();
    expect(result.url).toBe('http://localhost:3000');
    expect(result.port).toBe(3000);
  });
});
