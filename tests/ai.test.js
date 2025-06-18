/**
 * AI module tests
 */
const { detectVulnerabilities, analyzeSourceCodeWithAI } = require('../lib/ai');

jest.mock('openai', () => {
  return {
    OpenAI: jest.fn().mockImplementation(() => {
      return {
        chat: {
          completions: {
            create: jest.fn().mockResolvedValue({
              choices: [
                {
                  message: {
                    content: JSON.stringify({
                      vulnerabilities: [
                        {
                          id: 'AI-001',
                          title: 'Test SQL Injection',
                          severity: 'high',
                          description: 'Found potential SQL injection'
                        }
                      ],
                      insights: [
                        {
                          title: 'Security Best Practice',
                          description: 'Use prepared statements to prevent SQL injection'
                        }
                      ]
                    })
                  }
                }
              ]
            })
          }
        }
      };
    })
  };
});

describe('AI Module Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('detectVulnerabilities should return vulnerabilities and insights', async () => {
    const result = await detectVulnerabilities('example.com', {
      useAI: true,
      usePatterns: true
    });

    expect(result).toBeDefined();
    expect(result.vulnerabilities).toBeDefined();
    expect(result.insights).toBeDefined();
    expect(result.vulnerabilities.length).toBeGreaterThanOrEqual(0);
    expect(result.insights.length).toBeGreaterThanOrEqual(0);
  });

  test('analyzeSourceCodeWithAI should detect vulnerabilities', async () => {
    const code = `
    app.get('/users/:id', function(req, res) {
      const userId = req.params.id;
      const query = 'SELECT * FROM users WHERE id = ' + userId;
      db.execute(query);
    });
    `;

    const result = await analyzeSourceCodeWithAI([{ path: 'test.js', content: code }]);
    
    expect(result).toBeDefined();
    expect(result.vulnerabilities).toBeDefined();
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    expect(result.vulnerabilities[0].title).toContain('SQL Injection');
  });
});
