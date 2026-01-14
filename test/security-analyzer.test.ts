import { describe, it, expect } from 'vitest';
import { SecurityAnalyzer } from '../src/security-analyzer.js';

describe('SecurityAnalyzer', () => {
  const analyzer = new SecurityAnalyzer();

  describe('scanForVulnerabilities', () => {
    it('should detect SQL injection', () => {
      const code = `
        const userId = req.params.id;
        const query = "SELECT * FROM users WHERE id = " + userId;
        db.query(query);
      `;

      const result = analyzer.scanForVulnerabilities(code);
      expect(result.findings.some(f => f.type === 'sqlInjection')).toBe(true);
    });

    it('should detect XSS via innerHTML', () => {
      const code = `
        const userInput = document.getElementById('input').value;
        element.innerHTML = userInput;
      `;

      const result = analyzer.scanForVulnerabilities(code);
      expect(result.findings.some(f => f.type === 'xss')).toBe(true);
    });

    it('should detect hardcoded credentials', () => {
      const code = `
        const config = {
          apiKey: "sk-1234567890abcdef1234567890",
          password: "supersecret123"
        };
      `;

      const result = analyzer.scanForVulnerabilities(code);
      expect(result.findings.some(f => f.type === 'hardcodedCredentials')).toBe(true);
    });

    it('should detect weak cryptography', () => {
      const code = `
        const crypto = require('crypto');
        const hash = crypto.createHash('md5').update(password).digest('hex');
      `;

      const result = analyzer.scanForVulnerabilities(code);
      expect(result.findings.some(f => f.type === 'weakCrypto')).toBe(true);
    });

    it('should return no findings for secure code', () => {
      const code = `
        const userId = req.params.id;
        const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
        element.textContent = sanitizedInput;
      `;

      const result = analyzer.scanForVulnerabilities(code);
      expect(result.findings.length).toBe(0);
    });
  });

  describe('detectSensitiveData', () => {
    it('should detect AWS access keys', () => {
      const code = `
        const awsKey = "AKIAIOSFODNN7EXAMPLE";
      `;

      const result = analyzer.detectSensitiveData(code);
      expect(result.findings.some(f => f.type === 'AWS Access Key')).toBe(true);
    });

    it('should detect GitHub tokens', () => {
      const code = `
        const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
      `;

      const result = analyzer.detectSensitiveData(code);
      expect(result.findings.some(f => f.type === 'GitHub Token')).toBe(true);
    });

    it('should mask sensitive data in findings', () => {
      const code = `
        const awsKey = "AKIAIOSFODNN7EXAMPLE";
      `;

      const result = analyzer.detectSensitiveData(code);
      const finding = result.findings.find(f => f.type === 'AWS Access Key');
      expect(finding?.match).toContain('****');
    });
  });

  describe('getRecommendations', () => {
    it('should return SQL injection recommendations', () => {
      const rec = analyzer.getRecommendations('sqlInjection');
      expect(rec.vulnerabilityType).toBe('SQL Injection');
      expect(rec.recommendations.length).toBeGreaterThan(0);
    });

    it('should return XSS recommendations', () => {
      const rec = analyzer.getRecommendations('xss');
      expect(rec.vulnerabilityType).toBe('Cross-Site Scripting (XSS)');
    });

    it('should return generic recommendations for unknown types', () => {
      const rec = analyzer.getRecommendations('unknownVulnerability');
      expect(rec.recommendations.length).toBeGreaterThan(0);
    });
  });
});
