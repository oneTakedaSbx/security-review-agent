import axios, { AxiosInstance } from 'axios';

export interface SonarIssue {
  key: string;
  rule: string;
  severity: string;
  component: string;
  project: string;
  line?: number;
  message: string;
  type: string;
  status: string;
  creationDate: string;
}

export interface SecurityHotspot {
  key: string;
  component: string;
  project: string;
  securityCategory: string;
  vulnerabilityProbability: string;
  status: string;
  line?: number;
  message: string;
}

export interface DependencyVulnerability {
  key: string;
  severity: string;
  component: string;
  cve?: string;
  cwe?: string;
  message: string;
}

export class SonarCloudClient {
  private client: AxiosInstance;
  private organization: string;

  constructor(token: string, organization: string, baseUrl: string = 'https://sonarcloud.io') {
    this.organization = organization;
    this.client = axios.create({
      baseURL: `${baseUrl}/api`,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });
  }

  async getIssues(
    projectKey: string,
    severity?: string,
    type?: string
  ): Promise<{ issues: SonarIssue[]; total: number; summary: string }> {
    try {
      const params: Record<string, string> = {
        componentKeys: projectKey,
        organization: this.organization,
        ps: '100',
        resolved: 'false',
      };

      if (severity) params.severities = severity;
      if (type) params.types = type;

      const response = await this.client.get('/issues/search', { params });

      const issues: SonarIssue[] = response.data.issues.map((issue: any) => ({
        key: issue.key,
        rule: issue.rule,
        severity: issue.severity,
        component: issue.component,
        project: issue.project,
        line: issue.line,
        message: issue.message,
        type: issue.type,
        status: issue.status,
        creationDate: issue.creationDate,
      }));

      const summary = this.generateIssuesSummary(issues);

      return {
        issues,
        total: response.data.total,
        summary,
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`SonarCloud API error: ${error.response?.status} - ${error.message}`);
      }
      throw error;
    }
  }

  async getSecurityHotspots(
    projectKey: string,
    status?: string
  ): Promise<{ hotspots: SecurityHotspot[]; total: number; summary: string }> {
    try {
      const params: Record<string, string> = {
        projectKey,
        organization: this.organization,
        ps: '100',
      };

      if (status) params.status = status;

      const response = await this.client.get('/hotspots/search', { params });

      const hotspots: SecurityHotspot[] = response.data.hotspots.map((hotspot: any) => ({
        key: hotspot.key,
        component: hotspot.component,
        project: hotspot.project,
        securityCategory: hotspot.securityCategory,
        vulnerabilityProbability: hotspot.vulnerabilityProbability,
        status: hotspot.status,
        line: hotspot.line,
        message: hotspot.message,
      }));

      const summary = this.generateHotspotsSummary(hotspots);

      return {
        hotspots,
        total: response.data.paging?.total || hotspots.length,
        summary,
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`SonarCloud API error: ${error.response?.status} - ${error.message}`);
      }
      throw error;
    }
  }

  async getDependencyVulnerabilities(
    projectKey: string
  ): Promise<{ vulnerabilities: DependencyVulnerability[]; total: number; summary: string }> {
    try {
      // Get vulnerability issues (type = VULNERABILITY)
      const response = await this.client.get('/issues/search', {
        params: {
          componentKeys: projectKey,
          organization: this.organization,
          types: 'VULNERABILITY',
          ps: '100',
          resolved: 'false',
        },
      });

      const vulnerabilities: DependencyVulnerability[] = response.data.issues
        .filter((issue: any) => issue.rule.includes('security') || issue.tags?.includes('cwe'))
        .map((issue: any) => ({
          key: issue.key,
          severity: issue.severity,
          component: issue.component,
          cve: issue.tags?.find((t: string) => t.startsWith('cve-')),
          cwe: issue.tags?.find((t: string) => t.startsWith('cwe-')),
          message: issue.message,
        }));

      const summary = this.generateVulnerabilitiesSummary(vulnerabilities);

      return {
        vulnerabilities,
        total: vulnerabilities.length,
        summary,
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`SonarCloud API error: ${error.response?.status} - ${error.message}`);
      }
      throw error;
    }
  }

  async getProjectAnalysis(projectKey: string): Promise<any> {
    try {
      const response = await this.client.get('/measures/component', {
        params: {
          component: projectKey,
          metricKeys:
            'security_rating,vulnerabilities,security_hotspots,security_hotspots_reviewed',
        },
      });

      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`SonarCloud API error: ${error.response?.status} - ${error.message}`);
      }
      throw error;
    }
  }

  private generateIssuesSummary(issues: SonarIssue[]): string {
    const bySeverity = issues.reduce(
      (acc, issue) => {
        acc[issue.severity] = (acc[issue.severity] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    const byType = issues.reduce(
      (acc, issue) => {
        acc[issue.type] = (acc[issue.type] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    return `Found ${issues.length} issues:\n` +
      `By Severity: ${JSON.stringify(bySeverity)}\n` +
      `By Type: ${JSON.stringify(byType)}`;
  }

  private generateHotspotsSummary(hotspots: SecurityHotspot[]): string {
    const byCategory = hotspots.reduce(
      (acc, h) => {
        acc[h.securityCategory] = (acc[h.securityCategory] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    const byProbability = hotspots.reduce(
      (acc, h) => {
        acc[h.vulnerabilityProbability] = (acc[h.vulnerabilityProbability] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    return `Found ${hotspots.length} security hotspots:\n` +
      `By Category: ${JSON.stringify(byCategory)}\n` +
      `By Probability: ${JSON.stringify(byProbability)}`;
  }

  private generateVulnerabilitiesSummary(vulnerabilities: DependencyVulnerability[]): string {
    const bySeverity = vulnerabilities.reduce(
      (acc, v) => {
        acc[v.severity] = (acc[v.severity] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    const withCve = vulnerabilities.filter((v) => v.cve).length;

    return `Found ${vulnerabilities.length} dependency vulnerabilities:\n` +
      `By Severity: ${JSON.stringify(bySeverity)}\n` +
      `With CVE: ${withCve}`;
  }
}
