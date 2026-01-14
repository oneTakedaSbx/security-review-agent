# Security Review Agent

[![DEVX-10](https://img.shields.io/badge/Jira-DEVX--10-blue)](https://onetakeda.atlassian.net/browse/DEVX-10)

A GitHub Copilot extensibility agent that identifies potential security vulnerabilities using SonarCloud integration.

## Features

- 🔍 **Scan code for common security vulnerabilities** - SQL injection, XSS, CSRF, etc.
- 🛡️ **Suggest secure coding practices** - Based on OWASP guidelines
- 🔐 **Identify sensitive data handling issues** - API keys, passwords, PII detection
- 📋 **Recommend security best practices** - Authentication, authorization, encryption
- ⚠️ **Flag potential injection vulnerabilities** - Command, SQL, LDAP, XPath injection
- 📦 **Check for secure dependency usage** - CVE scanning via SonarCloud

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Review Agent                         │
├─────────────────────────────────────────────────────────────────┤
│  GitHub Copilot Chat Extension (@security-review)               │
│       │                                                          │
│       ├── MCP Server (SonarCloud Integration)                   │
│       │    ├── Get project issues                               │
│       │    ├── Get security hotspots                            │
│       │    ├── Analyze code quality                             │
│       │    └── Check dependencies (OWASP)                       │
│       │                                                          │
│       └── Built-in Security Analysis                            │
│            ├── Pattern-based vulnerability detection            │
│            ├── OWASP Top 10 checks                              │
│            └── Sensitive data detection                         │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Node.js 18+
- GitHub Copilot license
- SonarCloud account and token

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/oneTakedaSbx/security-review-agent.git
   cd security-review-agent
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your SonarCloud credentials
   ```

4. Build the agent:
   ```bash
   npm run build
   ```

### Configure VS Code MCP

Add to your VS Code `settings.json` or `mcp.json`:

```json
{
  "mcp": {
    "servers": {
      "security-review": {
        "command": "node",
        "args": ["path/to/security-review-agent/dist/mcp-server.js"],
        "env": {
          "SONARCLOUD_TOKEN": "your-token",
          "SONARCLOUD_ORGANIZATION": "your-org"
        }
      }
    }
  }
}
```

## Usage

In GitHub Copilot Chat, use the `@security-review` agent:

```
@security-review analyze this file for security vulnerabilities
@security-review check for SQL injection risks
@security-review scan dependencies for CVEs
@security-review review authentication implementation
```

## MCP Tools Available

| Tool | Description |
|------|-------------|
| `scan_vulnerabilities` | Scan code for OWASP Top 10 vulnerabilities |
| `get_sonar_issues` | Fetch security issues from SonarCloud |
| `get_security_hotspots` | Get security hotspots from SonarCloud |
| `check_dependencies` | Check dependencies for known CVEs |
| `analyze_sensitive_data` | Detect hardcoded secrets and PII |
| `get_secure_recommendations` | Get secure coding recommendations |

## Development

```bash
# Run in development mode
npm run dev

# Run tests
npm test

# Lint code
npm run lint
```

## License

MIT
