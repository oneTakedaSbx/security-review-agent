#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { SonarCloudClient } from './sonarcloud-client.js';
import { SecurityAnalyzer } from './security-analyzer.js';
import { z } from 'zod';

// Tool definitions
const TOOLS: Tool[] = [
  {
    name: 'scan_vulnerabilities',
    description: 'Scan code for OWASP Top 10 security vulnerabilities including SQL injection, XSS, CSRF, and more',
    inputSchema: {
      type: 'object',
      properties: {
        code: {
          type: 'string',
          description: 'The code to analyze for vulnerabilities',
        },
        language: {
          type: 'string',
          description: 'Programming language (e.g., javascript, python, java, csharp)',
        },
      },
      required: ['code'],
    },
  },
  {
    name: 'get_sonar_issues',
    description: 'Fetch security issues from SonarCloud for a specific project',
    inputSchema: {
      type: 'object',
      properties: {
        projectKey: {
          type: 'string',
          description: 'SonarCloud project key',
        },
        severity: {
          type: 'string',
          enum: ['INFO', 'MINOR', 'MAJOR', 'CRITICAL', 'BLOCKER'],
          description: 'Filter by severity level',
        },
        type: {
          type: 'string',
          enum: ['BUG', 'VULNERABILITY', 'CODE_SMELL', 'SECURITY_HOTSPOT'],
          description: 'Filter by issue type',
        },
      },
      required: ['projectKey'],
    },
  },
  {
    name: 'get_security_hotspots',
    description: 'Get security hotspots from SonarCloud that need manual review',
    inputSchema: {
      type: 'object',
      properties: {
        projectKey: {
          type: 'string',
          description: 'SonarCloud project key',
        },
        status: {
          type: 'string',
          enum: ['TO_REVIEW', 'REVIEWED'],
          description: 'Filter by review status',
        },
      },
      required: ['projectKey'],
    },
  },
  {
    name: 'check_dependencies',
    description: 'Check project dependencies for known CVEs and security vulnerabilities',
    inputSchema: {
      type: 'object',
      properties: {
        projectKey: {
          type: 'string',
          description: 'SonarCloud project key',
        },
      },
      required: ['projectKey'],
    },
  },
  {
    name: 'analyze_sensitive_data',
    description: 'Detect hardcoded secrets, API keys, passwords, and PII in code',
    inputSchema: {
      type: 'object',
      properties: {
        code: {
          type: 'string',
          description: 'The code to analyze for sensitive data',
        },
      },
      required: ['code'],
    },
  },
  {
    name: 'get_secure_recommendations',
    description: 'Get secure coding recommendations based on detected issues',
    inputSchema: {
      type: 'object',
      properties: {
        vulnerabilityType: {
          type: 'string',
          description: 'Type of vulnerability to get recommendations for',
        },
        language: {
          type: 'string',
          description: 'Programming language for context-specific recommendations',
        },
      },
      required: ['vulnerabilityType'],
    },
  },
];

class SecurityReviewServer {
  private server: Server;
  private sonarClient: SonarCloudClient;
  private analyzer: SecurityAnalyzer;

  constructor() {
    this.server = new Server(
      {
        name: 'security-review-agent',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.sonarClient = new SonarCloudClient(
      process.env.SONARCLOUD_TOKEN || '',
      process.env.SONARCLOUD_ORGANIZATION || '',
      process.env.SONARCLOUD_BASE_URL || 'https://sonarcloud.io'
    );

    this.analyzer = new SecurityAnalyzer();

    this.setupHandlers();
  }

  private setupHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: TOOLS,
    }));

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'scan_vulnerabilities':
            return await this.handleScanVulnerabilities(args);
          case 'get_sonar_issues':
            return await this.handleGetSonarIssues(args);
          case 'get_security_hotspots':
            return await this.handleGetSecurityHotspots(args);
          case 'check_dependencies':
            return await this.handleCheckDependencies(args);
          case 'analyze_sensitive_data':
            return await this.handleAnalyzeSensitiveData(args);
          case 'get_secure_recommendations':
            return await this.handleGetRecommendations(args);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${errorMessage}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  private async handleScanVulnerabilities(args: unknown) {
    const schema = z.object({
      code: z.string(),
      language: z.string().optional(),
    });
    const { code, language } = schema.parse(args);
    const results = this.analyzer.scanForVulnerabilities(code, language);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(results, null, 2),
        },
      ],
    };
  }

  private async handleGetSonarIssues(args: unknown) {
    const schema = z.object({
      projectKey: z.string(),
      severity: z.string().optional(),
      type: z.string().optional(),
    });
    const { projectKey, severity, type } = schema.parse(args);
    const issues = await this.sonarClient.getIssues(projectKey, severity, type);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(issues, null, 2),
        },
      ],
    };
  }

  private async handleGetSecurityHotspots(args: unknown) {
    const schema = z.object({
      projectKey: z.string(),
      status: z.string().optional(),
    });
    const { projectKey, status } = schema.parse(args);
    const hotspots = await this.sonarClient.getSecurityHotspots(projectKey, status);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(hotspots, null, 2),
        },
      ],
    };
  }

  private async handleCheckDependencies(args: unknown) {
    const schema = z.object({
      projectKey: z.string(),
    });
    const { projectKey } = schema.parse(args);
    const vulnerabilities = await this.sonarClient.getDependencyVulnerabilities(projectKey);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(vulnerabilities, null, 2),
        },
      ],
    };
  }

  private async handleAnalyzeSensitiveData(args: unknown) {
    const schema = z.object({
      code: z.string(),
    });
    const { code } = schema.parse(args);
    const findings = this.analyzer.detectSensitiveData(code);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(findings, null, 2),
        },
      ],
    };
  }

  private async handleGetRecommendations(args: unknown) {
    const schema = z.object({
      vulnerabilityType: z.string(),
      language: z.string().optional(),
    });
    const { vulnerabilityType, language } = schema.parse(args);
    const recommendations = this.analyzer.getRecommendations(vulnerabilityType, language);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(recommendations, null, 2),
        },
      ],
    };
  }

  async run(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Security Review Agent MCP server running on stdio');
  }
}

const server = new SecurityReviewServer();
server.run().catch(console.error);
