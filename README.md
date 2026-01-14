# 🔒 Security Review Agent

> A GitHub Copilot custom agent for identifying security vulnerabilities using SonarCloud rules and OWASP guidelines.

[![DEVX-10](https://img.shields.io/badge/Jira-DEVX--10-blue)](https://onetakeda.atlassian.net/browse/DEVX-10)
[![SonarCloud](https://img.shields.io/badge/SonarCloud-Rules-orange)](https://rules.sonarsource.com/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)](https://owasp.org/Top10/)

## 📋 Overview

As defined in **DEVX-10**, this agent helps developers write more secure code by:

- ✅ Scanning code for common security vulnerabilities
- ✅ Suggesting secure coding practices
- ✅ Identifying sensitive data handling issues
- ✅ Recommending security best practices
- ✅ Flagging potential injection vulnerabilities
- ✅ Checking for secure dependency usage

## 🚀 Quick Start

### Installation

1. Ensure you have GitHub Copilot enabled in your VS Code
2. The agent is automatically available org-wide through the `.github` repository

### Usage

In GitHub Copilot Chat, use the `@security-review` agent:

```
@security-review /analyze
```

## 🎯 Available Commands

| Command | Description |
|---------|-------------|
| `/analyze` | Analyze selected code or workspace for vulnerabilities |
| `/scan` | Comprehensive security scan of codebase |
| `/check-dependencies` | Check for known CVEs in dependencies |
| `/best-practices` | Get security recommendations for current context |

## 📊 Example Usage

### Analyze a specific file
```
@security-review /analyze src/auth/login.py
```

### Scan entire workspace
```
@security-review /scan
```

### Check dependencies
```
@security-review /check-dependencies
```

### Get best practices for API development
```
@security-review /best-practices for REST API authentication
```

## 🛡️ Security Categories Covered

### OWASP Top 10 (2021)

| Category | Coverage |
|----------|----------|
| A01: Broken Access Control | ✅ |
| A02: Cryptographic Failures | ✅ |
| A03: Injection | ✅ |
| A04: Insecure Design | ✅ |
| A05: Security Misconfiguration | ✅ |
| A06: Vulnerable Components | ✅ |
| A07: Auth Failures | ✅ |
| A08: Software/Data Integrity | ✅ |
| A09: Logging Failures | ✅ |
| A10: SSRF | ✅ |

### SonarCloud Rules Integration

- **S3649** - SQL Injection
- **S2076** - Command Injection
- **S5131** - XSS
- **S2068** - Hardcoded Credentials
- **S4790** - Weak Hashing
- **S5542** - Weak Encryption
- **S5135** - Insecure Deserialization
- **S2083** - Path Traversal
- And many more...

## 📈 Sample Output

```
## Security Analysis Report

### Summary
- 🔴 Critical: 1 issue
- 🟠 High: 2 issues  
- 🟡 Medium: 3 issues
- 🔵 Low: 1 issue

### Findings

#### [CRITICAL] SQL Injection Vulnerability
- **File:** `src/database/queries.py:45`
- **Rule:** S3649
- **Description:** User input directly concatenated into SQL query
- **Recommendation:** Use parameterized queries
```

## 🔗 Integration with SonarCloud

This agent is designed to complement your SonarCloud setup:

1. **Development Time:** Use `@security-review` while coding
2. **Pre-commit:** Quick security check before committing
3. **CI/CD:** Full SonarCloud scan on PR/merge
4. **Quality Gates:** Enforce standards with SonarCloud

## 📚 Resources

- [OWASP Top 10](https://owasp.org/Top10/)
- [SonarCloud Security Rules](https://rules.sonarsource.com/)
- [CWE Database](https://cwe.mitre.org/)
- [NIST Guidelines](https://csrc.nist.gov/)

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines and submit PRs.

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

*Built for Takeda Developer Experience Platform (DEVX-10)*
