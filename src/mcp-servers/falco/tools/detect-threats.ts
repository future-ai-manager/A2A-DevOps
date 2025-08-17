import { BaseTool } from '@mcp-servers/base/Tool';
import { ToolResult, SecurityEvent } from '@core/types';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export class DetectThreatsTool extends BaseTool {
  readonly name = 'detect_threats';
  readonly description = 'Detect security threats using Falco runtime security monitoring';
  readonly inputSchema = {
    type: 'object' as const,
    properties: {
      timeRange: {
        type: 'string',
        description: 'Time range to search for threats (e.g., "1h", "24h", "7d")',
        default: '1h'
      },
      severity: {
        type: 'string',
        enum: ['all', 'low', 'medium', 'high', 'critical'],
        description: 'Minimum severity level to include',
        default: 'medium'
      },
      ruleFilter: {
        type: 'string',
        description: 'Optional filter for specific Falco rules (regex pattern)'
      },
      namespace: {
        type: 'string',
        description: 'Kubernetes namespace to filter events (if applicable)'
      },
      maxEvents: {
        type: 'number',
        description: 'Maximum number of events to return',
        default: 100,
        minimum: 1,
        maximum: 1000
      }
    },
    required: []
  };

  async execute(params: any): Promise<ToolResult> {
    if (!this.validateParams(params)) {
      return this.createErrorResult('Invalid parameters provided');
    }

    try {
      const {
        timeRange = '1h',
        severity = 'medium',
        ruleFilter,
        namespace,
        maxEvents = 100
      } = params;

      // Check if Falco is available
      const falcoAvailable = await this.checkFalcoAvailability();
      if (!falcoAvailable) {
        return this.createErrorResult('Falco is not installed or not accessible. Please install Falco and ensure it is running.');
      }

      // Get Falco events
      const events = await this.getFalcoEvents(timeRange, severity, ruleFilter, namespace, maxEvents);
      
      // Analyze and categorize threats
      const threatAnalysis = this.analyzeThreatEvents(events);

      return this.createSuccessResult({
        summary: {
          totalEvents: events.length,
          criticalThreats: events.filter(e => e.severity === 'critical').length,
          highThreats: events.filter(e => e.severity === 'high').length,
          mediumThreats: events.filter(e => e.severity === 'medium').length,
          lowThreats: events.filter(e => e.severity === 'low').length,
          timeRange,
          namespace: namespace || 'all'
        },
        events: events.slice(0, maxEvents),
        analysis: threatAnalysis,
        recommendations: this.generateRecommendations(threatAnalysis)
      });

    } catch (error) {
      return this.createErrorResult(`Failed to detect threats: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async checkFalcoAvailability(): Promise<boolean> {
    try {
      await execAsync('falco --version');
      return true;
    } catch {
      // Try alternative methods (e.g., systemctl status falco, docker logs falco)
      try {
        await execAsync('systemctl is-active falco');
        return true;
      } catch {
        try {
          await execAsync('docker ps --filter name=falco --quiet');
          return true;
        } catch {
          return false;
        }
      }
    }
  }

  private async getFalcoEvents(
    timeRange: string,
    severity: string,
    ruleFilter?: string,
    namespace?: string,
    maxEvents: number = 100
  ): Promise<SecurityEvent[]> {
    const events: SecurityEvent[] = [];

    try {
      // Method 1: Try to read from Falco log files
      const logEvents = await this.readFalcoLogs(timeRange, severity, ruleFilter, namespace);
      events.push(...logEvents);

      // Method 2: If no events from logs, try Falco syslog output
      if (events.length === 0) {
        const syslogEvents = await this.readFalcoSyslog(timeRange, severity);
        events.push(...syslogEvents);
      }

      // Method 3: If still no events, try Falco gRPC API (if available)
      if (events.length === 0) {
        const grpcEvents = await this.getFalcoGRPCEvents(timeRange, severity);
        events.push(...grpcEvents);
      }

    } catch (error) {
      // If all methods fail, throw error - no mock data
      throw new Error(`Falco not accessible: ${error instanceof Error ? error.message : 'Unknown error'}. Please ensure Falco is installed and running.`);
    }

    // Sort by timestamp (most recent first) and limit results
    return events
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, maxEvents);
  }

  private async readFalcoLogs(
    timeRange: string,
    severity: string,
    ruleFilter?: string,
    namespace?: string
  ): Promise<SecurityEvent[]> {
    const events: SecurityEvent[] = [];
    const logPaths = [
      '/var/log/falco.log',
      '/var/log/syslog',
      '/var/log/messages'
    ];

    for (const logPath of logPaths) {
      try {
        const timeFilter = this.getTimeFilter(timeRange);
        let command = `grep "falco" ${logPath}`;
        
        if (timeFilter) {
          command += ` | ${timeFilter}`;
        }
        
        const { stdout } = await execAsync(command);
        const logEvents = this.parseFalcoLogEntries(stdout, severity, ruleFilter, namespace);
        events.push(...logEvents);
        
        if (events.length > 0) break; // Use first successful log source
      } catch {
        continue; // Try next log file
      }
    }

    return events;
  }

  private async readFalcoSyslog(timeRange: string, severity: string): Promise<SecurityEvent[]> {
    try {
      const { stdout } = await execAsync('journalctl -u falco --output=json --no-pager');
      const lines = stdout.trim().split('\n').filter(line => line.trim());
      const events: SecurityEvent[] = [];

      for (const line of lines) {
        try {
          const logEntry = JSON.parse(line);
          if (logEntry.MESSAGE && logEntry.MESSAGE.includes('falco')) {
            const event = this.parseJournalEntry(logEntry, severity);
            if (event) events.push(event);
          }
        } catch {
          continue;
        }
      }

      return events;
    } catch {
      return [];
    }
  }

  private async getFalcoGRPCEvents(timeRange: string, severity: string): Promise<SecurityEvent[]> {
    // This would implement gRPC client for Falco API
    // For now, return empty array as this requires additional setup
    return [];
  }


  private parseFalcoLogEntries(
    logContent: string,
    severity: string,
    ruleFilter?: string,
    namespace?: string
  ): SecurityEvent[] {
    const events: SecurityEvent[] = [];
    const lines = logContent.split('\n').filter(line => line.trim());

    for (const line of lines) {
      try {
        // Try to parse as JSON first (Falco JSON output)
        if (line.includes('{') && line.includes('}')) {
          const jsonMatch = line.match(/\{.*\}/);
          if (jsonMatch) {
            const eventData = JSON.parse(jsonMatch[0]);
            const event = this.convertFalcoJsonToEvent(eventData);
            if (event && this.passesFilters(event, severity, ruleFilter, namespace)) {
              events.push(event);
            }
          }
        }
        // Parse plain text format
        else {
          const event = this.parsePlainTextLogEntry(line);
          if (event && this.passesFilters(event, severity, ruleFilter, namespace)) {
            events.push(event);
          }
        }
      } catch {
        continue;
      }
    }

    return events;
  }

  private convertFalcoJsonToEvent(falcoData: any): SecurityEvent | null {
    if (!falcoData.rule || !falcoData.time) return null;

    return {
      id: `falco-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: falcoData.time,
      severity: this.mapFalcoSeverity(falcoData.priority || 'Notice'),
      rule: falcoData.rule,
      description: falcoData.output || falcoData.rule,
      source: 'falco',
      tags: falcoData.tags || [],
      metadata: {
        priority: falcoData.priority,
        source: falcoData.source,
        hostname: falcoData.hostname,
        ...falcoData.output_fields
      }
    };
  }

  private parsePlainTextLogEntry(line: string): SecurityEvent | null {
    // Parse plain text Falco log format
    const timestampMatch = line.match(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
    const priorityMatch = line.match(/Priority:(\w+)/i);
    const ruleMatch = line.match(/Rule:([^()]+)/i);
    
    if (!timestampMatch || !ruleMatch) return null;

    return {
      id: `falco-text-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: timestampMatch[1],
      severity: this.mapFalcoSeverity(priorityMatch ? priorityMatch[1] : 'Notice'),
      rule: ruleMatch[1].trim(),
      description: line,
      source: 'falco',
      tags: [],
      metadata: {}
    };
  }

  private parseJournalEntry(logEntry: any, severity: string): SecurityEvent | null {
    if (!logEntry.MESSAGE) return null;

    return {
      id: `falco-journal-${logEntry.__CURSOR || Date.now()}`,
      timestamp: logEntry.__REALTIME_TIMESTAMP ? 
        new Date(parseInt(logEntry.__REALTIME_TIMESTAMP) / 1000).toISOString() : 
        new Date().toISOString(),
      severity: 'medium' as any,
      rule: 'Journal Entry',
      description: logEntry.MESSAGE,
      source: 'falco-journal',
      tags: ['journal'],
      metadata: {
        unit: logEntry._SYSTEMD_UNIT,
        pid: logEntry._PID,
        hostname: logEntry._HOSTNAME
      }
    };
  }

  private mapFalcoSeverity(falcoPriority: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (falcoPriority.toLowerCase()) {
      case 'emergency':
      case 'alert':
        return 'critical';
      case 'critical':
      case 'error':
        return 'high';
      case 'warning':
        return 'medium';
      case 'notice':
      case 'info':
      case 'debug':
      default:
        return 'low';
    }
  }

  private passesFilters(
    event: SecurityEvent,
    severity: string,
    ruleFilter?: string,
    namespace?: string
  ): boolean {
    // Check severity filter
    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const minSeverityIndex = severityOrder.indexOf(severity);
    const eventSeverityIndex = severityOrder.indexOf(event.severity);
    
    if (severity !== 'all' && eventSeverityIndex < minSeverityIndex) {
      return false;
    }

    // Check rule filter
    if (ruleFilter && !new RegExp(ruleFilter, 'i').test(event.rule)) {
      return false;
    }

    // Check namespace filter
    if (namespace && event.metadata?.namespace && event.metadata.namespace !== namespace) {
      return false;
    }

    return true;
  }

  private getTimeFilter(timeRange: string): string | null {
    // Convert time range to appropriate grep/awk filter
    // This is a simplified implementation
    const now = new Date();
    let hoursBack = 1;

    if (timeRange.endsWith('h')) {
      hoursBack = parseInt(timeRange.replace('h', ''));
    } else if (timeRange.endsWith('d')) {
      hoursBack = parseInt(timeRange.replace('d', '')) * 24;
    }

    // Return null for now - would need more sophisticated time filtering
    return null;
  }

  private analyzeThreatEvents(events: SecurityEvent[]): any {
    const analysis = {
      topRules: this.getTopTriggeredRules(events),
      severityDistribution: this.getSeverityDistribution(events),
      timeDistribution: this.getTimeDistribution(events),
      sourceAnalysis: this.getSourceAnalysis(events),
      riskScore: this.calculateRiskScore(events)
    };

    return analysis;
  }

  private getTopTriggeredRules(events: SecurityEvent[]): any[] {
    const ruleCounts = new Map<string, number>();
    
    for (const event of events) {
      ruleCounts.set(event.rule, (ruleCounts.get(event.rule) || 0) + 1);
    }

    return Array.from(ruleCounts.entries())
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([rule, count]) => ({ rule, count }));
  }

  private getSeverityDistribution(events: SecurityEvent[]): Record<string, number> {
    const distribution: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };

    for (const event of events) {
      distribution[event.severity]++;
    }

    return distribution;
  }

  private getTimeDistribution(events: SecurityEvent[]): any {
    // Group events by hour for trend analysis
    const hourlyDistribution = new Map<string, number>();
    
    for (const event of events) {
      const hour = new Date(event.timestamp).getHours();
      const hourKey = `${hour}:00`;
      hourlyDistribution.set(hourKey, (hourlyDistribution.get(hourKey) || 0) + 1);
    }

    return Array.from(hourlyDistribution.entries())
      .sort(([a], [b]) => parseInt(a) - parseInt(b))
      .map(([hour, count]) => ({ hour, count }));
  }

  private getSourceAnalysis(events: SecurityEvent[]): any {
    const sourceMap = new Map<string, number>();
    
    for (const event of events) {
      const source = event.metadata?.hostname || event.metadata?.container_id || 'unknown';
      sourceMap.set(source, (sourceMap.get(source) || 0) + 1);
    }

    return Array.from(sourceMap.entries())
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([source, count]) => ({ source, count }));
  }

  private calculateRiskScore(events: SecurityEvent[]): number {
    if (events.length === 0) return 0;

    let totalScore = 0;
    const severityScores = { critical: 10, high: 7, medium: 4, low: 1 };

    for (const event of events) {
      totalScore += severityScores[event.severity] || 1;
    }

    // Normalize to 0-100 scale
    const maxPossibleScore = events.length * 10;
    return Math.round((totalScore / maxPossibleScore) * 100);
  }

  private generateRecommendations(analysis: any): string[] {
    const recommendations: string[] = [];

    if (analysis.riskScore > 80) {
      recommendations.push('HIGH RISK: Immediate attention required. Multiple critical security events detected.');
    } else if (analysis.riskScore > 60) {
      recommendations.push('MEDIUM RISK: Review security events and implement additional monitoring.');
    } else if (analysis.riskScore > 30) {
      recommendations.push('LOW RISK: Monitor trends and ensure security policies are up to date.');
    }

    if (analysis.topRules.length > 0) {
      const topRule = analysis.topRules[0];
      recommendations.push(`Most triggered rule: "${topRule.rule}" (${topRule.count} times) - Review and potentially tune this rule.`);
    }

    if (analysis.severityDistribution.critical > 0) {
      recommendations.push(`${analysis.severityDistribution.critical} critical threats detected - Investigate immediately.`);
    }

    return recommendations;
  }
}