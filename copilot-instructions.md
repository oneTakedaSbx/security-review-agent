# Security Review Agent - Copilot Instructions

This is a GitHub Copilot extensibility agent for security code review.

## Agent Name
`@security-review`

## Capabilities

When users invoke `@security-review`, the agent can:

1. **Scan for vulnerabilities** - Analyze code for OWASP Top 10 vulnerabilities
2. **Check SonarCloud** - Fetch real issues and hotspots from SonarCloud
3. **Detect secrets** - Find hardcoded credentials and sensitive data
4. **Provide recommendations** - Give secure coding guidance

## Example Prompts

- `@security-review analyze this file for security issues`
- `@security-review check for SQL injection vulnerabilities`
- `@security-review get SonarCloud issues for my-project`
- `@security-review detect any hardcoded secrets`
- `@security-review what's the secure way to handle user passwords?`

## MCP Tools

The agent provides these MCP tools:

| Tool | Purpose |
|------|--------|
| `scan_vulnerabilities` | Pattern-based vulnerability detection |
| `get_sonar_issues` | Fetch issues from SonarCloud |
| `get_security_hotspots` | Get security hotspots needing review |
| `check_dependencies` | Check for CVEs in dependencies |
| `analyze_sensitive_data` | Detect secrets and PII |
| `get_secure_recommendations` | Get secure coding guidance |

## Integration with SonarCloud

The agent integrates with SonarCloud to:
- Pull real-time security issues
- Get security hotspot status
- Check dependency vulnerabilities
- Provide context from existing static analysis
