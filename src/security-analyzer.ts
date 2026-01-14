export interface VulnerabilityFinding {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  line?: number;
  column?: number;
  message: string;
  cwe?: string;
  owaspCategory?: string;
  recommendation: string;
}

export interface SensitiveDataFinding {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  line: number;
  match: string;
  message: string;
  recommendation: string;
}

export interface SecurityRecommendation {
  vulnerabilityType: string;
  description: string;
  recommendations: string[];
  secureExample?: string;
  insecureExample?: string;
  references: string[];
}

// Vulnerability detection patterns
const VULNERABILITY_PATTERNS = {
  sqlInjection: {
    patterns: [
      /\b(execute|query|raw|exec)\s*\(\s*["'`].*\$\{.*\}.*["'`]\s*\)/gi,
      /\b(execute|query|raw|exec)\s*\(\s*[^)]*\+\s*[^)]+\)/gi,
      /\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b[^;]*\$\{/gi,
      /cursor\.execute\s*\(\s*["'].*%s.*["']\s*%/gi,
      /\.format\(.*\).*\.(execute|query)/gi,
    ],
    severity: 'CRITICAL' as const,
    cwe: 'CWE-89',
    owaspCategory: 'A03:2021-Injection',
  },
  xss: {
    patterns: [
      /innerHTML\s*=\s*[^"']/gi,
      /document\.write\s*\(/gi,
      /\$\(.*\)\.html\s*\(/gi,
      /dangerouslySetInnerHTML/gi,
      /v-html\s*=/gi,
      /\[innerHTML\]/gi,
    ],
    severity: 'HIGH' as const,
    cwe: 'CWE-79',
    owaspCategory: 'A03:2021-Injection',
  },
  commandInjection: {
    patterns: [
      /child_process\.exec\s*\(\s*[^)]*\+/gi,
      /subprocess\.(call|run|Popen)\s*\(\s*[^)]*\+/gi,
      /os\.system\s*\(/gi,
      /Runtime\.getRuntime\(\)\.exec\s*\(/gi,
      /eval\s*\([^)]*\$\{/gi,
      /shell=True/gi,
    ],
    severity: 'CRITICAL' as const,
    cwe: 'CWE-78',
    owaspCategory: 'A03:2021-Injection',
  },
  pathTraversal: {
    patterns: [
      /\.\.[\/\\]/g,
      /fs\.(read|write|append).*\+.*req\./gi,
      /open\s*\(\s*[^)]*\+/gi,
      /path\.join\s*\(\s*[^)]*req\./gi,
    ],
    severity: 'HIGH' as const,
    cwe: 'CWE-22',
    owaspCategory: 'A01:2021-Broken Access Control',
  },
  insecureDeserialization: {
    patterns: [
      /pickle\.loads?\s*\(/gi,
      /yaml\.load\s*\([^)]*Loader/gi,
      /ObjectInputStream/gi,
      /unserialize\s*\(/gi,
      /JSON\.parse\s*\(\s*req\./gi,
    ],
    severity: 'HIGH' as const,
    cwe: 'CWE-502',
    owaspCategory: 'A08:2021-Software and Data Integrity Failures',
  },
  weakCrypto: {
    patterns: [
      /\b(MD5|SHA1|DES|RC4)\b/gi,
      /createHash\s*\(\s*["']md5["']\s*\)/gi,
      /hashlib\.(md5|sha1)\s*\(/gi,
      /crypto\.createCipher\s*\(/gi,
    ],
    severity: 'MEDIUM' as const,
    cwe: 'CWE-327',
    owaspCategory: 'A02:2021-Cryptographic Failures',
  },
  hardcodedCredentials: {
    patterns: [
      /password\s*[:=]\s*["'][^"']+["']/gi,
      /api[_-]?key\s*[:=]\s*["'][^"']+["']/gi,
      /secret\s*[:=]\s*["'][^"']+["']/gi,
      /token\s*[:=]\s*["'][A-Za-z0-9+\/=]{20,}["']/gi,
      /private[_-]?key\s*[:=]\s*["']/gi,
    ],
    severity: 'CRITICAL' as const,
    cwe: 'CWE-798',
    owaspCategory: 'A07:2021-Identification and Authentication Failures',
  },
  insecureRandomness: {
    patterns: [
      /Math\.random\s*\(/g,
      /random\.random\s*\(/gi,
      /new Random\s*\(/gi,
      /rand\s*\(\s*\)/gi,
    ],
    severity: 'MEDIUM' as const,
    cwe: 'CWE-330',
    owaspCategory: 'A02:2021-Cryptographic Failures',
  },
  openRedirect: {
    patterns: [
      /redirect\s*\(\s*req\.(query|params|body)/gi,
      /location\.href\s*=\s*[^"']/gi,
      /window\.location\s*=\s*[^"']/gi,
      /res\.redirect\s*\(\s*req\./gi,
    ],
    severity: 'MEDIUM' as const,
    cwe: 'CWE-601',
    owaspCategory: 'A01:2021-Broken Access Control',
  },
  xxe: {
    patterns: [
      /DocumentBuilderFactory(?!.*setFeature)/gi,
      /XMLReader(?!.*setFeature)/gi,
      /etree\.parse\s*\(/gi,
      /parseXML(?!.*defusedxml)/gi,
    ],
    severity: 'HIGH' as const,
    cwe: 'CWE-611',
    owaspCategory: 'A05:2021-Security Misconfiguration',
  },
};

// Sensitive data patterns
const SENSITIVE_DATA_PATTERNS = [
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'CRITICAL' as const,
  },
  {
    name: 'AWS Secret Key',
    pattern: /[A-Za-z0-9\/+=]{40}/g,
    severity: 'CRITICAL' as const,
  },
  {
    name: 'GitHub Token',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    severity: 'CRITICAL' as const,
  },
  {
    name: 'Private Key',
    pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    severity: 'CRITICAL' as const,
  },
  {
    name: 'Generic API Key',
    pattern: /["']?api[_-]?key["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{20,}["']/gi,
    severity: 'HIGH' as const,
  },
  {
    name: 'Bearer Token',
    pattern: /Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g,
    severity: 'HIGH' as const,
  },
  {
    name: 'Connection String',
    pattern: /(mongodb|mysql|postgresql|redis):\/\/[^\s"']+:[^\s"']+@/gi,
    severity: 'CRITICAL' as const,
  },
  {
    name: 'Email Address',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    severity: 'LOW' as const,
  },
  {
    name: 'IP Address',
    pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
    severity: 'LOW' as const,
  },
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g,
    severity: 'HIGH' as const,
  },
];

// Security recommendations database
const RECOMMENDATIONS: Record<string, SecurityRecommendation> = {
  sqlInjection: {
    vulnerabilityType: 'SQL Injection',
    description: 'SQL injection occurs when untrusted data is sent to an interpreter as part of a command or query.',
    recommendations: [
      'Use parameterized queries (prepared statements)',
      'Use an ORM that automatically escapes input',
      'Validate and sanitize all user input',
      'Apply the principle of least privilege to database accounts',
      'Use stored procedures with parameterized inputs',
    ],
    secureExample: `// Secure: Using parameterized query
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);`,
    insecureExample: `// Insecure: String concatenation
const result = await db.query('SELECT * FROM users WHERE id = ' + userId);`,
    references: [
      'https://owasp.org/www-community/attacks/SQL_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html',
    ],
  },
  xss: {
    vulnerabilityType: 'Cross-Site Scripting (XSS)',
    description: 'XSS attacks occur when an attacker can inject malicious scripts into web pages viewed by other users.',
    recommendations: [
      'Encode output data appropriately for the context (HTML, JavaScript, URL, CSS)',
      'Use Content Security Policy (CSP) headers',
      'Use modern frameworks that auto-escape by default (React, Angular, Vue)',
      'Validate and sanitize all user input',
      'Use HTTPOnly and Secure flags for cookies',
    ],
    secureExample: `// Secure: Using textContent
element.textContent = userInput;

// React automatically escapes
<div>{userInput}</div>`,
    insecureExample: `// Insecure: Using innerHTML
element.innerHTML = userInput;

// React dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userInput}} />`,
    references: [
      'https://owasp.org/www-community/attacks/xss/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
    ],
  },
  commandInjection: {
    vulnerabilityType: 'Command Injection',
    description: 'Command injection occurs when an attacker can execute arbitrary commands on the host operating system.',
    recommendations: [
      'Avoid calling OS commands directly from application code',
      'If OS commands are necessary, use parameterized APIs',
      'Validate and sanitize all user input',
      'Use allowlists for permitted command arguments',
      'Run application with minimal privileges',
    ],
    secureExample: `// Secure: Using parameterized child_process
const { execFile } = require('child_process');
execFile('ls', ['-la', directory], callback);`,
    insecureExample: `// Insecure: String concatenation with exec
const { exec } = require('child_process');
exec('ls -la ' + userInput, callback);`,
    references: [
      'https://owasp.org/www-community/attacks/Command_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html',
    ],
  },
  hardcodedCredentials: {
    vulnerabilityType: 'Hardcoded Credentials',
    description: 'Hardcoded credentials in source code can be discovered and exploited by attackers.',
    recommendations: [
      'Use environment variables for sensitive configuration',
      'Use a secrets management service (AWS Secrets Manager, HashiCorp Vault)',
      'Never commit credentials to version control',
      'Use .gitignore to exclude configuration files with secrets',
      'Rotate credentials regularly',
    ],
    secureExample: `// Secure: Using environment variables
const apiKey = process.env.API_KEY;`,
    insecureExample: `// Insecure: Hardcoded credentials
const apiKey = 'sk-1234567890abcdef';`,
    references: [
      'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
      'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    ],
  },
  weakCrypto: {
    vulnerabilityType: 'Weak Cryptography',
    description: 'Using weak or broken cryptographic algorithms can lead to data exposure.',
    recommendations: [
      'Use strong algorithms: AES-256, SHA-256 or higher, RSA-2048+',
      'Use well-tested cryptographic libraries',
      'Never implement custom cryptography',
      'Use authenticated encryption (GCM mode)',
      'Keep cryptographic libraries updated',
    ],
    secureExample: `// Secure: Using strong algorithm
const hash = crypto.createHash('sha256').update(data).digest('hex');`,
    insecureExample: `// Insecure: Using weak algorithm
const hash = crypto.createHash('md5').update(data).digest('hex');`,
    references: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
    ],
  },
};

export class SecurityAnalyzer {
  scanForVulnerabilities(code: string, language?: string): {
    findings: VulnerabilityFinding[];
    summary: string;
    riskLevel: string;
  } {
    const findings: VulnerabilityFinding[] = [];
    const lines = code.split('\n');

    for (const [vulnType, config] of Object.entries(VULNERABILITY_PATTERNS)) {
      for (const pattern of config.patterns) {
        // Reset the pattern
        pattern.lastIndex = 0;

        let match;
        while ((match = pattern.exec(code)) !== null) {
          // Find line number
          const beforeMatch = code.substring(0, match.index);
          const lineNumber = beforeMatch.split('\n').length;

          findings.push({
            type: vulnType,
            severity: config.severity,
            line: lineNumber,
            message: `Potential ${this.formatVulnType(vulnType)} detected`,
            cwe: config.cwe,
            owaspCategory: config.owaspCategory,
            recommendation: RECOMMENDATIONS[vulnType]?.recommendations[0] || 'Review and fix this security issue',
          });
        }
      }
    }

    // Remove duplicates
    const uniqueFindings = this.deduplicateFindings(findings);

    const summary = this.generateSummary(uniqueFindings);
    const riskLevel = this.calculateRiskLevel(uniqueFindings);

    return { findings: uniqueFindings, summary, riskLevel };
  }

  detectSensitiveData(code: string): {
    findings: SensitiveDataFinding[];
    summary: string;
  } {
    const findings: SensitiveDataFinding[] = [];

    for (const patternDef of SENSITIVE_DATA_PATTERNS) {
      patternDef.pattern.lastIndex = 0;
      let match;

      while ((match = patternDef.pattern.exec(code)) !== null) {
        const beforeMatch = code.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;

        // Mask the sensitive data
        const maskedMatch = this.maskSensitiveData(match[0]);

        findings.push({
          type: patternDef.name,
          severity: patternDef.severity,
          line: lineNumber,
          match: maskedMatch,
          message: `Potential ${patternDef.name} found in code`,
          recommendation: 'Remove sensitive data and use environment variables or a secrets manager',
        });
      }
    }

    const summary = `Found ${findings.length} potential sensitive data exposures: ` +
      `${findings.filter(f => f.severity === 'CRITICAL').length} critical, ` +
      `${findings.filter(f => f.severity === 'HIGH').length} high, ` +
      `${findings.filter(f => f.severity === 'MEDIUM').length} medium, ` +
      `${findings.filter(f => f.severity === 'LOW').length} low`;

    return { findings, summary };
  }

  getRecommendations(
    vulnerabilityType: string,
    language?: string
  ): SecurityRecommendation {
    const normalizedType = vulnerabilityType.toLowerCase().replace(/[\s-_]/g, '');

    // Find matching recommendation
    for (const [key, recommendation] of Object.entries(RECOMMENDATIONS)) {
      if (key.toLowerCase().includes(normalizedType) ||
          recommendation.vulnerabilityType.toLowerCase().replace(/[\s-_]/g, '').includes(normalizedType)) {
        return recommendation;
      }
    }

    // Return generic recommendation if not found
    return {
      vulnerabilityType,
      description: 'Security vulnerability that should be addressed.',
      recommendations: [
        'Review the code for security issues',
        'Follow OWASP security guidelines',
        'Consult with security team',
        'Run static analysis tools',
      ],
      references: [
        'https://owasp.org/www-project-top-ten/',
        'https://cwe.mitre.org/',
      ],
    };
  }

  private formatVulnType(type: string): string {
    return type
      .replace(/([A-Z])/g, ' $1')
      .replace(/^./, str => str.toUpperCase())
      .trim();
  }

  private deduplicateFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
    const seen = new Set<string>();
    return findings.filter(finding => {
      const key = `${finding.type}-${finding.line}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private generateSummary(findings: VulnerabilityFinding[]): string {
    if (findings.length === 0) {
      return 'No security vulnerabilities detected.';
    }

    const bySeverity = findings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const byType = findings.reduce((acc, f) => {
      acc[f.type] = (acc[f.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return `Found ${findings.length} potential security issues:\n` +
      `Severity: ${JSON.stringify(bySeverity)}\n` +
      `Types: ${JSON.stringify(byType)}`;
  }

  private calculateRiskLevel(findings: VulnerabilityFinding[]): string {
    if (findings.some(f => f.severity === 'CRITICAL')) return 'CRITICAL';
    if (findings.some(f => f.severity === 'HIGH')) return 'HIGH';
    if (findings.some(f => f.severity === 'MEDIUM')) return 'MEDIUM';
    if (findings.some(f => f.severity === 'LOW')) return 'LOW';
    return 'NONE';
  }

  private maskSensitiveData(data: string): string {
    if (data.length <= 8) return '****';
    return data.substring(0, 4) + '****' + data.substring(data.length - 4);
  }
}
