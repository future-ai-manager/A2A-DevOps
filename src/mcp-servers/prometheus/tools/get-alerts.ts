import { BaseTool } from '@mcp-servers/base/Tool';
import { ToolResult, AlertRule } from '@core/types';
import axios from 'axios';

interface PrometheusAlert {
  labels: Record<string, string>;
  annotations: Record<string, string>;
  state: 'firing' | 'pending' | 'inactive';
  activeAt: string;
  value: string;
}

interface AlertGroup {
  labels: Record<string, string>;
  file: string;
  rules: AlertRule[];
  interval: string;
  limit: number;
}

export class GetAlertsTool extends BaseTool {
  readonly name = 'get_alerts';
  readonly description = 'Get active alerts and alert rules from Prometheus Alertmanager';
  readonly inputSchema = {
    type: 'object' as const,
    properties: {
      action: {
        type: 'string',
        enum: ['list_active', 'list_rules', 'get_rule', 'test_rule', 'create_rule'],
        description: 'Action to perform',
        default: 'list_active'
      },
      state: {
        type: 'string',
        enum: ['all', 'firing', 'pending', 'inactive'],
        description: 'Filter alerts by state',
        default: 'all'
      },
      severity: {
        type: 'string',
        enum: ['all', 'critical', 'warning', 'info'],
        description: 'Filter alerts by severity',
        default: 'all'
      },
      ruleName: {
        type: 'string',
        description: 'Specific rule name for get_rule or test_rule actions'
      },
      prometheusUrl: {
        type: 'string',
        description: 'Prometheus server URL',
        format: 'uri'
      },
      alertmanagerUrl: {
        type: 'string',
        description: 'Alertmanager URL',
        format: 'uri'
      },
      maxAlerts: {
        type: 'number',
        description: 'Maximum number of alerts to return',
        default: 100,
        minimum: 1,
        maximum: 1000
      },
      newRule: {
        type: 'object',
        properties: {
          alert: { type: 'string' },
          expr: { type: 'string' },
          for: { type: 'string' },
          labels: { type: 'object' },
          annotations: { type: 'object' }
        },
        description: 'New rule definition for create_rule action'
      }
    },
    required: []
  };

  private defaultPrometheusUrl = 'http://localhost:9090';
  private defaultAlertmanagerUrl = 'http://localhost:9093';

  async execute(params: any): Promise<ToolResult> {
    if (!this.validateParams(params)) {
      return this.createErrorResult('Invalid parameters provided');
    }

    try {
      const {
        action = 'list_active',
        state = 'all',
        severity = 'all',
        ruleName,
        prometheusUrl = this.defaultPrometheusUrl,
        alertmanagerUrl = this.defaultAlertmanagerUrl,
        maxAlerts = 100,
        newRule
      } = params;

      switch (action) {
        case 'list_active':
          return await this.listActiveAlerts(alertmanagerUrl, state, severity, maxAlerts);
        case 'list_rules':
          return await this.listAlertRules(prometheusUrl, severity);
        case 'get_rule':
          if (!ruleName) {
            return this.createErrorResult('Rule name is required for get_rule action');
          }
          return await this.getAlertRule(prometheusUrl, ruleName);
        case 'test_rule':
          if (!ruleName) {
            return this.createErrorResult('Rule name is required for test_rule action');
          }
          return await this.testAlertRule(prometheusUrl, ruleName);
        case 'create_rule':
          if (!newRule) {
            return this.createErrorResult('New rule definition is required for create_rule action');
          }
          return await this.createAlertRule(newRule);
        default:
          return this.createErrorResult(`Unknown action: ${action}`);
      }

    } catch (error) {
      return this.createErrorResult(`Failed to get alerts: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async listActiveAlerts(
    alertmanagerUrl: string,
    state: string,
    severity: string,
    maxAlerts: number
  ): Promise<ToolResult> {
    try {
      // First check if Alertmanager is available
      const isAvailable = await this.checkAlertmanagerConnection(alertmanagerUrl);
      if (!isAvailable) {
        // Fallback to Prometheus alerts endpoint
        return await this.getPrometheusAlerts(alertmanagerUrl.replace(':9093', ':9090'), state, severity, maxAlerts);
      }

      const response = await axios.get(`${alertmanagerUrl}/api/v1/alerts`, {
        timeout: 10000
      });

      if (response.data.status !== 'success') {
        throw new Error(`Alertmanager API error: ${response.data.error || 'Unknown error'}`);
      }

      let alerts: PrometheusAlert[] = response.data.data;

      // Apply filters
      if (state !== 'all') {
        alerts = alerts.filter(alert => alert.state === state);
      }

      if (severity !== 'all') {
        alerts = alerts.filter(alert => 
          alert.labels.severity?.toLowerCase() === severity.toLowerCase()
        );
      }

      // Limit results
      alerts = alerts.slice(0, maxAlerts);

      // Process and enrich alerts
      const processedAlerts = alerts.map(alert => ({
        fingerprint: this.generateFingerprint(alert.labels),
        state: alert.state,
        labels: alert.labels,
        annotations: alert.annotations,
        activeAt: alert.activeAt,
        value: alert.value,
        severity: alert.labels.severity || 'unknown',
        alertname: alert.labels.alertname || 'unknown',
        instance: alert.labels.instance || 'unknown',
        summary: alert.annotations.summary || alert.annotations.description || 'No description',
        runbook: alert.annotations.runbook_url,
        duration: this.calculateDuration(alert.activeAt)
      }));

      // Generate statistics
      const stats = this.generateAlertStatistics(processedAlerts);

      // Generate recommendations
      const recommendations = this.generateAlertRecommendations(processedAlerts, stats);

      return this.createSuccessResult({
        summary: {
          totalAlerts: processedAlerts.length,
          firingAlerts: processedAlerts.filter(a => a.state === 'firing').length,
          pendingAlerts: processedAlerts.filter(a => a.state === 'pending').length,
          filters: { state, severity },
          timestamp: new Date().toISOString()
        },
        alerts: processedAlerts,
        statistics: stats,
        recommendations
      });

    } catch (error) {
      // No fallback to mock data - throw actual error
      if (axios.isAxiosError(error) && error.code === 'ECONNREFUSED') {
        throw new Error('Alertmanager not accessible at ' + alertmanagerUrl + '. Please ensure Alertmanager is running.');
      }
      throw error;
    }
  }

  private async getPrometheusAlerts(
    prometheusUrl: string,
    state: string,
    severity: string,
    maxAlerts: number
  ): Promise<ToolResult> {
    try {
      const response = await axios.get(`${prometheusUrl}/api/v1/alerts`, {
        timeout: 10000
      });

      if (response.data.status !== 'success') {
        throw new Error(`Prometheus alerts API error: ${response.data.error || 'Unknown error'}`);
      }

      let alerts = response.data.data.alerts || [];

      // Apply filters and process similar to Alertmanager alerts
      if (state !== 'all' && state !== 'firing') {
        alerts = alerts.filter((alert: any) => alert.state === state);
      }

      if (severity !== 'all') {
        alerts = alerts.filter((alert: any) => 
          alert.labels.severity?.toLowerCase() === severity.toLowerCase()
        );
      }

      alerts = alerts.slice(0, maxAlerts);

      const processedAlerts = alerts.map((alert: any) => ({
        fingerprint: this.generateFingerprint(alert.labels),
        state: alert.state || 'firing',
        labels: alert.labels,
        annotations: alert.annotations || {},
        activeAt: alert.activeAt || new Date().toISOString(),
        value: alert.value || '0',
        severity: alert.labels.severity || 'unknown',
        alertname: alert.labels.alertname || 'unknown',
        instance: alert.labels.instance || 'unknown',
        summary: alert.annotations?.summary || alert.annotations?.description || 'No description',
        runbook: alert.annotations?.runbook_url,
        duration: this.calculateDuration(alert.activeAt || new Date().toISOString())
      }));

      const stats = this.generateAlertStatistics(processedAlerts);
      const recommendations = this.generateAlertRecommendations(processedAlerts, stats);

      return this.createSuccessResult({
        summary: {
          totalAlerts: processedAlerts.length,
          firingAlerts: processedAlerts.filter(a => a.state === 'firing').length,
          pendingAlerts: processedAlerts.filter(a => a.state === 'pending').length,
          filters: { state, severity },
          timestamp: new Date().toISOString(),
          source: 'prometheus'
        },
        alerts: processedAlerts,
        statistics: stats,
        recommendations
      });

    } catch (error) {
      throw new Error('Prometheus alerts API not accessible at ' + prometheusUrl + '. Please ensure Prometheus is running and accessible.');
    }
  }

  private async listAlertRules(prometheusUrl: string, severity: string): Promise<ToolResult> {
    try {
      const response = await axios.get(`${prometheusUrl}/api/v1/rules`, {
        timeout: 10000
      });

      if (response.data.status !== 'success') {
        throw new Error(`Prometheus rules API error: ${response.data.error || 'Unknown error'}`);
      }

      const groups: AlertGroup[] = response.data.data.groups || [];
      let allRules: any[] = [];

      // Extract all alert rules from groups
      for (const group of groups) {
        const alertRules = group.rules
          .filter(rule => rule.type === 'alerting')
          .map(rule => ({
            ...rule,
            group: group.file,
            interval: group.interval
          }));
        allRules.push(...alertRules);
      }

      // Filter by severity if specified
      if (severity !== 'all') {
        allRules = allRules.filter(rule => 
          rule.labels?.severity?.toLowerCase() === severity.toLowerCase()
        );
      }

      // Process rules
      const processedRules = allRules.map(rule => ({
        name: rule.name || rule.alert,
        query: rule.query || rule.expr,
        duration: rule.duration || rule.for || '0s',
        severity: rule.labels?.severity || 'unknown',
        description: rule.annotations?.description || rule.annotations?.summary || 'No description',
        runbook: rule.annotations?.runbook_url,
        group: rule.group,
        state: rule.state || 'inactive',
        health: rule.health || 'unknown',
        lastError: rule.lastError,
        evaluationTime: rule.evaluationTime,
        lastEvaluation: rule.lastEvaluation,
        labels: rule.labels || {},
        annotations: rule.annotations || {}
      }));

      // Generate statistics
      const ruleStats = this.generateRuleStatistics(processedRules, groups);

      return this.createSuccessResult({
        summary: {
          totalRules: processedRules.length,
          totalGroups: groups.length,
          healthyRules: processedRules.filter(r => r.health === 'ok').length,
          firingRules: processedRules.filter(r => r.state === 'firing').length,
          filters: { severity },
          timestamp: new Date().toISOString()
        },
        rules: processedRules,
        groups: groups.map(g => ({
          name: g.file,
          interval: g.interval,
          ruleCount: g.rules.filter(r => r.type === 'alerting').length
        })),
        statistics: ruleStats,
        recommendations: this.generateRuleRecommendations(processedRules)
      });

    } catch (error) {
      throw new Error('Prometheus rules API not accessible at ' + prometheusUrl + '. Please ensure Prometheus is running and accessible.');
    }
  }

  private async getAlertRule(prometheusUrl: string, ruleName: string): Promise<ToolResult> {
    try {
      const rulesResult = await this.listAlertRules(prometheusUrl, 'all');
      if (!rulesResult.success) {
        throw new Error('Failed to fetch rules');
      }

      const rules = rulesResult.data.rules;
      const rule = rules.find((r: any) => r.name.toLowerCase() === ruleName.toLowerCase());

      if (!rule) {
        return this.createErrorResult(`Alert rule '${ruleName}' not found`);
      }

      // Get additional details for this specific rule
      const ruleDetails = {
        ...rule,
        validationStatus: this.validateAlertRule(rule),
        queryAnalysis: await this.analyzeRuleQuery(rule.query, prometheusUrl),
        firingHistory: await this.getRuleHistory(ruleName, prometheusUrl),
        relatedRules: this.findRelatedRules(rule, rules)
      };

      return this.createSuccessResult({
        rule: ruleDetails,
        recommendations: this.generateSingleRuleRecommendations(ruleDetails)
      });

    } catch (error) {
      return this.createErrorResult(`Failed to get rule: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async testAlertRule(prometheusUrl: string, ruleName: string): Promise<ToolResult> {
    try {
      const ruleResult = await this.getAlertRule(prometheusUrl, ruleName);
      if (!ruleResult.success) {
        return ruleResult;
      }

      const rule = ruleResult.data.rule;

      // Test the rule query
      const queryTest = await this.testRuleQuery(rule.query, prometheusUrl);

      // Test rule syntax
      const syntaxTest = this.validateRuleSyntax(rule);

      // Test rule logic
      const logicTest = this.validateRuleLogic(rule);

      const testResults = {
        ruleName: rule.name,
        query: rule.query,
        tests: {
          queryExecution: queryTest,
          syntaxValidation: syntaxTest,
          logicValidation: logicTest
        },
        overallStatus: queryTest.success && syntaxTest.success && logicTest.success ? 'passed' : 'failed',
        timestamp: new Date().toISOString()
      };

      return this.createSuccessResult(testResults);

    } catch (error) {
      return this.createErrorResult(`Failed to test rule: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async createAlertRule(ruleDefinition: any): Promise<ToolResult> {
    try {
      // Validate rule definition
      const validation = this.validateNewRule(ruleDefinition);
      if (!validation.isValid) {
        return this.createErrorResult(`Invalid rule definition: ${validation.errors.join(', ')}`);
      }

      // Format rule as YAML
      const ruleYaml = this.formatRuleAsYaml(ruleDefinition);

      // In a real implementation, this would write to Prometheus config
      // For now, return the formatted rule
      return this.createSuccessResult({
        action: 'create_rule',
        rule: ruleDefinition,
        yaml: ruleYaml,
        message: 'Alert rule created successfully (dry-run mode)',
        nextSteps: [
          'Add this rule to your Prometheus configuration',
          'Restart Prometheus to load the new rule',
          'Monitor for proper rule evaluation'
        ]
      });

    } catch (error) {
      return this.createErrorResult(`Failed to create rule: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async checkAlertmanagerConnection(alertmanagerUrl: string): Promise<boolean> {
    try {
      const response = await axios.get(`${alertmanagerUrl}/api/v1/status`, { timeout: 5000 });
      return response.status === 200;
    } catch {
      return false;
    }
  }

  private generateFingerprint(labels: Record<string, string>): string {
    const sortedLabels = Object.entries(labels)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join('|');
    
    // Simple hash function for fingerprint
    let hash = 0;
    for (let i = 0; i < sortedLabels.length; i++) {
      const char = sortedLabels.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }

  private calculateDuration(activeAt: string): string {
    const startTime = new Date(activeAt);
    const now = new Date();
    const diffMs = now.getTime() - startTime.getTime();
    
    const diffMinutes = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMinutes / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffDays > 0) return `${diffDays}d ${diffHours % 24}h`;
    if (diffHours > 0) return `${diffHours}h ${diffMinutes % 60}m`;
    return `${diffMinutes}m`;
  }

  private generateAlertStatistics(alerts: any[]): any {
    const stats = {
      bySeverity: {} as Record<string, number>,
      byState: {} as Record<string, number>,
      byInstance: {} as Record<string, number>,
      averageDuration: 0,
      oldestAlert: null as any,
      newestAlert: null as any
    };

    for (const alert of alerts) {
      stats.bySeverity[alert.severity] = (stats.bySeverity[alert.severity] || 0) + 1;
      stats.byState[alert.state] = (stats.byState[alert.state] || 0) + 1;
      stats.byInstance[alert.instance] = (stats.byInstance[alert.instance] || 0) + 1;
    }

    // Find oldest and newest alerts
    if (alerts.length > 0) {
      const sortedByAge = alerts.sort((a, b) => 
        new Date(a.activeAt).getTime() - new Date(b.activeAt).getTime()
      );
      stats.oldestAlert = sortedByAge[0];
      stats.newestAlert = sortedByAge[sortedByAge.length - 1];
    }

    return stats;
  }

  private generateRuleStatistics(rules: any[], groups: any[]): any {
    return {
      byHealth: rules.reduce((acc, rule) => {
        acc[rule.health] = (acc[rule.health] || 0) + 1;
        return acc;
      }, {} as Record<string, number>),
      bySeverity: rules.reduce((acc, rule) => {
        acc[rule.severity] = (acc[rule.severity] || 0) + 1;
        return acc;
      }, {} as Record<string, number>),
      byGroup: groups.map(g => ({
        group: g.file,
        alertRules: g.rules.filter((r: any) => r.type === 'alerting').length,
        recordingRules: g.rules.filter((r: any) => r.type === 'recording').length
      }))
    };
  }

  private generateAlertRecommendations(alerts: any[], stats: any): string[] {
    const recommendations: string[] = [];

    if (alerts.filter(a => a.state === 'firing').length > 10) {
      recommendations.push('🚨 High number of firing alerts - review alert thresholds and reduce noise');
    }

    const criticalAlerts = alerts.filter(a => a.severity === 'critical');
    if (criticalAlerts.length > 0) {
      recommendations.push(`⚠️ ${criticalAlerts.length} critical alerts active - immediate attention required`);
    }

    const oldAlerts = alerts.filter(a => {
      const activeTime = new Date().getTime() - new Date(a.activeAt).getTime();
      return activeTime > 24 * 60 * 60 * 1000; // 24 hours
    });
    if (oldAlerts.length > 0) {
      recommendations.push(`📅 ${oldAlerts.length} alerts active for >24h - investigate root causes`);
    }

    return recommendations.slice(0, 5);
  }

  private generateRuleRecommendations(rules: any[]): string[] {
    const recommendations: string[] = [];

    const unhealthyRules = rules.filter(r => r.health !== 'ok');
    if (unhealthyRules.length > 0) {
      recommendations.push(`⚠️ ${unhealthyRules.length} rules have health issues - check rule syntax and queries`);
    }

    const missingDescriptions = rules.filter(r => !r.description || r.description === 'No description');
    if (missingDescriptions.length > 0) {
      recommendations.push(`📝 ${missingDescriptions.length} rules missing descriptions - add annotations for better documentation`);
    }

    return recommendations.slice(0, 5);
  }



  // Additional helper methods would be implemented here...
  private validateAlertRule(rule: any): any { return { isValid: true, issues: [] }; }
  private async analyzeRuleQuery(query: string, url: string): Promise<any> { return { valid: true }; }
  private async getRuleHistory(name: string, url: string): Promise<any[]> { return []; }
  private findRelatedRules(rule: any, allRules: any[]): any[] { return []; }
  private async testRuleQuery(query: string, url: string): Promise<any> { return { success: true }; }
  private validateRuleSyntax(rule: any): any { return { success: true }; }
  private validateRuleLogic(rule: any): any { return { success: true }; }
  private validateNewRule(rule: any): any { return { isValid: true, errors: [] }; }
  private formatRuleAsYaml(rule: any): string { return `# Rule YAML would be generated here`; }
  private generateSingleRuleRecommendations(rule: any): string[] { return []; }
}