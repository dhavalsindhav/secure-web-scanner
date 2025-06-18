/**
 * API Security tests
 */
const { scanApi, analyzeApiSpec } = require('../lib/apisec');

jest.mock('swagger-parser', () => {
  return {
    validate: jest.fn().mockResolvedValue({
      info: { title: 'Test API', version: '1.0.1' },
      paths: {
        '/users': {
          get: { responses: { 200: { description: 'OK' } } },
          post: { responses: { 201: { description: 'Created' } } }
        }
      }
    })
  };
});

describe('API Security Module Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('analyzeApiSpec should detect API security issues', async () => {
    const result = await analyzeApiSpec('./swagger.json');

    expect(result).toBeDefined();
    expect(result.title).toBe('Test API');
    expect(result.version).toBe('1.0.1');
    expect(result.endpoints).toBeDefined();
    expect(result.endpoints.length).toBeGreaterThan(0);
  });

  test('scanApi should work with discover option', async () => {
    // Mock the implementation
    const mockScan = jest.spyOn(global, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({})
    });

    const result = await scanApi('https://example.com', { discover: true });
    
    expect(result).toBeDefined();
    expect(result.endpoints).toBeDefined();
    
    mockScan.mockRestore();
  });
});
