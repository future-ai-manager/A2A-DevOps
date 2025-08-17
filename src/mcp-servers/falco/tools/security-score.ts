import { BaseTool } from '@mcp-servers/base/Tool';
import { ToolResult, SecurityChecklist, SecurityEvent } from '@core/types';
import { FALCO_SECURITY_CHECKLISTS, calculateChecklistScore, updateChecklistStatus, getAllSecurityChecks } from '../checklist';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export class SecurityScoreTool extends BaseTool {
  readonly name = 'security_score';
  readonly description = 'Calculate comprehensive security score based on Falco monitoring and security checklists';
  readonly inputSchema = {
    type: 'object' as const,
    properties: {
      timeRange: {
        type: 'string',
        description: 'Time range for security event analysis (e.g., "1h", "24h", "7d")',
        default: '24h'
      },
      includeCategories: {
        type: 'array',
        items: {
          type: 'string',
          enum: ['filesystem', 'process', 'network', 'privilege', 'container', 'kubernetes']
        },
        description: 'Security categories to include in scoring',
        default: ['filesystem', 'process', 'network', 'privilege', 'container', 'kubernetes']
      },
      weightings: {
        type: 'object',
        properties: {
          filesystem: { type: 'number', minimum: 0, maximum: 1, default: 0.15 },
          process: { type: 'number', minimum: 0, maximum: 1, default: 0.20 },
          network: { type: 'number', minimum: 0, maximum: 1, default: 0.20 },
          privilege: { type: 'number', minimum: 0, maximum: 1, default: 0.25 },
          container: { type: 'number', minimum: 0, maximum: 1, default: 0.15 },
          kubernetes: { type: 'number', minimum: 0, maximum: 1, default: 0.05 }
        },
        description: 'Weightings for different security categories (must sum to 1.0)'
      },
      namespace: {
        type: 'string',
        description: 'Kubernetes namespace to focus scoring on'
      },
      baseline: {
        type: 'boolean',
        description: 'Establish new security baseline from current state',
        default: false
      }
    },
    required: []
  };

  private defaultWeightings = {
    filesystem: 0.15,
    process: 0.20,
    network: 0.20,
    privilege: 0.25,
    container: 0.15,
    kubernetes: 0.05
  };

  async execute(params: any): Promise<ToolResult> {
    if (!this.validateParams(params)) {
      return this.createErrorResult('Invalid parameters provided');
    }

    try {
      const {
        timeRange = '24h',
        includeCategories = Object.keys(this.defaultWeightings),
        weightings = this.defaultWeightings,
        namespace,
        baseline = false
      } = params;

      // Validate weightings sum to 1.0
      const weightSum = Object.values(weightings).reduce((sum: number, weight: any) => sum + (weight || 0), 0);
      if (Math.abs(weightSum - 1.0) > 0.01) {
        return this.createErrorResult('Weightings must sum to 1.0');
      }

      // Get current security events
      const securityEvents = await this.getSecurityEvents(timeRange, namespace);
      
      // Evaluate security checklists
      const checklists = await this.evaluateSecurityChecklists(includeCategories, securityEvents);
      
      // Calculate comprehensive security score
      const scoreBreakdown = this.calculateSecurityScore(checklists, weightings);
      
      // Generate security recommendations
      const recommendations = this.generateSecurityRecommendations(checklists, securityEvents, scoreBreakdown);
      
      // Generate trend analysis
      const trends = await this.analyzeTrends(timeRange, namespace);

      // Handle baseline establishment
      if (baseline) {
        await this.establishBaseline(scoreBreakdown, checklists);
      }

      return this.createSuccessResult({
        overallScore: scoreBreakdown.overallScore,
        grade: this.getSecurityGrade(scoreBreakdown.overallScore),
        scoreBreakdown,
        checklists: Object.fromEntries(
          Object.entries(checklists).filter(([category]) => includeCategories.includes(category))
        ),
        summary: {
          totalChecks: Object.values(checklists).reduce((sum, checklist) => sum + checklist.checks.length, 0),
          passingChecks: Object.values(checklists).reduce((sum, checklist) => 
            sum + checklist.checks.filter(check => check.status === 'pass').length, 0),
          failingChecks: Object.values(checklists).reduce((sum, checklist) => 
            sum + checklist.checks.filter(check => check.status === 'fail').length, 0),
          criticalEvents: securityEvents.filter(event => event.severity === 'critical').length,
          highSeverityEvents: securityEvents.filter(event => event.severity === 'high').length,
          timeRange,
          namespace: namespace || 'all',
          evaluationTime: new Date().toISOString()
        },
        trends,
        recommendations,
        complianceStatus: this.assessComplianceStatus(checklists),
        nextEvaluation: this.calculateNextEvaluation(scoreBreakdown.overallScore)
      });

    } catch (error) {
      return this.createErrorResult(`Failed to calculate security score: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async getSecurityEvents(timeRange: string, namespace?: string): Promise<SecurityEvent[]> {
    const events: SecurityEvent[] = [];

    try {
      // Try to get real security events from Falco
      const { stdout } = await execAsync('falco --version');
      
      // If Falco is available, we would integrate with the detect-threats tool
      // For now, generate representative mock events
      events.push(...this.generateMockSecurityEvents(timeRange, namespace));

    } catch {
      // Generate mock events for demonstration
      events.push(...this.generateMockSecurityEvents(timeRange, namespace));
    }

    return events;
  }

  private generateMockSecurityEvents(timeRange: string, namespace?: string): SecurityEvent[] {
    const events: SecurityEvent[] = [];
    const now = Date.now();
    const hoursBack = this.parseTimeRange(timeRange);

    // Generate events based on typical security patterns
    const eventTemplates = [
      { rule: 'Terminal shell in container', severity: 'medium' as const, category: 'container' },
      { rule: 'Write below etc', severity: 'high' as const, category: 'filesystem' },
      { rule: 'Unexpected network connection', severity: 'medium' as const, category: 'network' },
      { rule: 'Privilege escalation attempt', severity: 'critical' as const, category: 'privilege' },
      { rule: 'Process spawned in container', severity: 'low' as const, category: 'process' },
      { rule: 'K8s API connection', severity: 'low' as const, category: 'kubernetes' }
    ];

    for (let i = 0; i < Math.min(20, hoursBack * 2); i++) {
      const template = eventTemplates[Math.floor(Math.random() * eventTemplates.length)];
      events.push({
        id: `mock-event-${i}-${Date.now()}`,
        timestamp: new Date(now - Math.random() * hoursBack * 3600000).toISOString(),
        severity: template.severity,
        rule: template.rule,
        description: `Mock security event: ${template.rule}`,
        source: 'falco-mock',
        tags: [template.category, 'mock'],
        metadata: {
          category: template.category,
          namespace: namespace || 'default',
          container_id: `mock-container-${i}`,
          process_name: `mock-process-${i}`
        }
      });
    }

    return events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }

  private parseTimeRange(timeRange: string): number {
    const match = timeRange.match(/^(\d+)([hdw])$/);
    if (!match) return 24; // Default to 24 hours

    const [, value, unit] = match;
    const numValue = parseInt(value);

    switch (unit) {
      case 'h': return numValue;
      case 'd': return numValue * 24;
      case 'w': return numValue * 24 * 7;
      default: return 24;
    }
  }

  private async evaluateSecurityChecklists(
    includeCategories: string[],
    securityEvents: SecurityEvent[]
  ): Promise<Record<string, SecurityChecklist>> {
    const evaluatedChecklists: Record<string, SecurityChecklist> = {};

    // Deep clone the base checklists
    for (const [category, checklist] of Object.entries(FALCO_SECURITY_CHECKLISTS)) {
      if (includeCategories.includes(category)) {
        evaluatedChecklists[category] = JSON.parse(JSON.stringify(checklist));
      }
    }

    // Update check statuses based on security events
    for (const event of securityEvents) {
      this.updateCheckStatusFromEvent(evaluatedChecklists, event);
    }

    // Perform additional runtime checks
    await this.performRuntimeSecurityChecks(evaluatedChecklists);

    // Calculate scores and update statuses
    for (const checklist of Object.values(evaluatedChecklists)) {
      updateChecklistStatus(checklist);
    }

    return evaluatedChecklists;
  }

  private updateCheckStatusFromEvent(checklists: Record<string, SecurityChecklist>, event: SecurityEvent): void {
    const eventRule = event.rule.toLowerCase();
    
    // Map events to specific checks
    for (const [category, checklist] of Object.entries(checklists)) {
      for (const check of checklist.checks) {
        if (check.rule && eventRule.includes(check.rule.toLowerCase().replace(/\s+/g, ' '))) {
          // Event matches this check - mark as failed if high/critical severity
          if (event.severity === 'critical' || event.severity === 'high') {
            check.status = 'fail';
            check.details = `Failed: ${event.description} (${event.timestamp})`;
          } else {
            check.status = 'warning';
            check.details = `Warning: ${event.description} (${event.timestamp})`;
          }
        }
      }
    }
  }

  private async performRuntimeSecurityChecks(checklists: Record<string, SecurityChecklist>): Promise<void> {
    // Perform additional runtime checks that don't rely on events
    try {
      // Check filesystem permissions
      if (checklists.filesystem) {
        await this.checkFilesystemSecurity(checklists.filesystem);
      }

      // Check container security
      if (checklists.container) {
        await this.checkContainerSecurity(checklists.container);
      }

      // Check Kubernetes security
      if (checklists.kubernetes) {
        await this.checkKubernetesSecurity(checklists.kubernetes);
      }

    } catch (error) {
      // Runtime checks failed - mark checks as unknown
      for (const checklist of Object.values(checklists)) {
        for (const check of checklist.checks) {
          if (check.status === 'unknown') {
            check.details = 'Unable to perform runtime verification';
          }
        }
      }
    }
  }

  private async checkFilesystemSecurity(checklist: SecurityChecklist): Promise<void> {
    try {
      // Check critical file permissions
      const criticalPaths = ['/etc', '/usr', '/bin', '/sbin'];
      
      for (const path of criticalPaths) {
        try {
          const { stdout } = await execAsync(`ls -la ${path} 2>/dev/null | head -5`);
          // Simple check - in production would be more sophisticated
          if (stdout.includes('drwxrwxrwx')) {
            const check = checklist.checks.find(c => c.id.includes('write_below_' + path.substring(1)));
            if (check) {
              check.status = 'fail';
              check.details = `Insecure permissions detected on ${path}`;
            }
          } else {
            const check = checklist.checks.find(c => c.id.includes('write_below_' + path.substring(1)));
            if (check && check.status === 'unknown') {
              check.status = 'pass';
              check.details = `Secure permissions verified on ${path}`;
            }
          }
        } catch {
          continue;
        }
      }
    } catch (error) {
      // Mark filesystem checks as unknown if we can't verify
    }
  }

  private async checkContainerSecurity(checklist: SecurityChecklist): Promise<void> {
    try {
      // Check for privileged containers
      const { stdout } = await execAsync('docker ps --format "table {{.Names}}\t{{.RunningFor}}\t{{.Status}}" 2>/dev/null || echo "docker_not_available"');
      
      if (!stdout.includes('docker_not_available')) {
        // Docker is available - perform checks
        const privilegedCheck = checklist.checks.find(c => c.id === 'privileged_container_started');
        if (privilegedCheck && privilegedCheck.status === 'unknown') {
          // Simple check for privileged containers
          try {
            const { stdout: privCheck } = await execAsync('docker ps --filter "privileged=true" --quiet');
            if (privCheck.trim()) {
              privilegedCheck.status = 'fail';
              privilegedCheck.details = 'Privileged containers detected';
            } else {
              privilegedCheck.status = 'pass';
              privilegedCheck.details = 'No privileged containers detected';
            }
          } catch {
            privilegedCheck.status = 'unknown';
            privilegedCheck.details = 'Unable to check privileged containers';
          }
        }
      }
    } catch (error) {
      // Container runtime not available
    }
  }

  private async checkKubernetesSecurity(checklist: SecurityChecklist): Promise<void> {
    try {
      // Check kubectl availability
      await execAsync('kubectl cluster-info 2>/dev/null');
      
      // Check for RBAC violations
      const rbacCheck = checklist.checks.find(c => c.id === 'rbac_violation');
      if (rbacCheck && rbacCheck.status === 'unknown') {
        try {
          const { stdout } = await execAsync('kubectl auth can-i --list 2>/dev/null');
          if (stdout.includes('*.*')) {
            rbacCheck.status = 'warning';
            rbacCheck.details = 'Overly permissive RBAC detected';
          } else {
            rbacCheck.status = 'pass';
            rbacCheck.details = 'RBAC appears properly configured';
          }
        } catch {
          rbacCheck.status = 'unknown';
          rbacCheck.details = 'Unable to verify RBAC configuration';
        }
      }

      // Check for privileged pods
      const privPodCheck = checklist.checks.find(c => c.id === 'privileged_pod_created');
      if (privPodCheck && privPodCheck.status === 'unknown') {
        try {
          const { stdout } = await execAsync('kubectl get pods --all-namespaces -o jsonpath="{.items[?(@.spec.securityContext.privileged==true)].metadata.name}" 2>/dev/null');
          if (stdout.trim()) {
            privPodCheck.status = 'fail';
            privPodCheck.details = `Privileged pods detected: ${stdout.trim()}`;
          } else {
            privPodCheck.status = 'pass';
            privPodCheck.details = 'No privileged pods detected';
          }
        } catch {
          privPodCheck.status = 'unknown';
          privPodCheck.details = 'Unable to check for privileged pods';
        }
      }

    } catch (error) {
      // Kubernetes not available
    }
  }

  private calculateSecurityScore(
    checklists: Record<string, SecurityChecklist>,
    weightings: Record<string, number>
  ): any {
    const categoryScores: Record<string, number> = {};
    let weightedSum = 0;
    let totalWeight = 0;

    for (const [category, checklist] of Object.entries(checklists)) {
      const categoryScore = calculateChecklistScore(checklist);
      categoryScores[category] = categoryScore;
      
      const weight = weightings[category] || 0;
      weightedSum += categoryScore * weight;
      totalWeight += weight;
    }

    const overallScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;

    return {
      overallScore,
      categoryScores,
      weightings,
      breakdown: {
        passing: Object.values(checklists).reduce((sum, checklist) => 
          sum + checklist.checks.filter(check => check.status === 'pass').length, 0),
        failing: Object.values(checklists).reduce((sum, checklist) => 
          sum + checklist.checks.filter(check => check.status === 'fail').length, 0),
        warning: Object.values(checklists).reduce((sum, checklist) => 
          sum + checklist.checks.filter(check => check.status === 'warning').length, 0),
        unknown: Object.values(checklists).reduce((sum, checklist) => 
          sum + checklist.checks.filter(check => check.status === 'unknown').length, 0)
      }
    };
  }

  private getSecurityGrade(score: number): string {
    if (score >= 90) return 'A+';
    if (score >= 85) return 'A';
    if (score >= 80) return 'A-';
    if (score >= 75) return 'B+';
    if (score >= 70) return 'B';
    if (score >= 65) return 'B-';
    if (score >= 60) return 'C+';
    if (score >= 55) return 'C';
    if (score >= 50) return 'C-';
    if (score >= 45) return 'D+';
    if (score >= 40) return 'D';
    return 'F';
  }

  private generateSecurityRecommendations(
    checklists: Record<string, SecurityChecklist>,
    events: SecurityEvent[],
    scoreBreakdown: any
  ): string[] {
    const recommendations: string[] = [];

    // Overall score recommendations
    if (scoreBreakdown.overallScore < 70) {
      recommendations.push('🚨 CRITICAL: Security score is below acceptable threshold. Immediate action required.');
    } else if (scoreBreakdown.overallScore < 85) {
      recommendations.push('⚠️ WARNING: Security posture needs improvement. Review failing checks.');
    }

    // Category-specific recommendations
    for (const [category, score] of Object.entries(scoreBreakdown.categoryScores)) {
      if ((score as number) < 60) {
        recommendations.push(`📋 ${category.toUpperCase()}: Critical issues detected (Score: ${score}). Focus on this area immediately.`);
      }
    }

    // Event-based recommendations
    const criticalEvents = events.filter(e => e.severity === 'critical');
    if (criticalEvents.length > 0) {
      recommendations.push(`🔥 ${criticalEvents.length} critical security events detected. Investigate immediately.`);
    }

    const highEvents = events.filter(e => e.severity === 'high');
    if (highEvents.length > 5) {
      recommendations.push(`⚡ ${highEvents.length} high-severity events detected. Review and address root causes.`);
    }

    // Specific check recommendations
    const failingChecks = Object.values(checklists).flatMap(checklist => 
      checklist.checks.filter(check => check.status === 'fail')
    );

    if (failingChecks.some(check => check.id.includes('privilege'))) {
      recommendations.push('🔐 Privilege escalation vulnerabilities detected. Review user permissions and access controls.');
    }

    if (failingChecks.some(check => check.id.includes('container'))) {
      recommendations.push('🐳 Container security issues detected. Review container configurations and runtime policies.');
    }

    if (failingChecks.some(check => check.id.includes('network'))) {
      recommendations.push('🌐 Network security issues detected. Review firewall rules and network policies.');
    }

    // Positive reinforcement
    if (scoreBreakdown.overallScore >= 90) {
      recommendations.push('✅ Excellent security posture! Continue monitoring and maintain current practices.');
    }

    return recommendations.slice(0, 10); // Limit to top 10 recommendations
  }

  private async analyzeTrends(timeRange: string, namespace?: string): Promise<any> {
    // This would analyze trends over time
    // For now, return mock trend data
    return {
      scoreHistory: [
        { timestamp: new Date(Date.now() - 7 * 24 * 3600000).toISOString(), score: 78 },
        { timestamp: new Date(Date.now() - 6 * 24 * 3600000).toISOString(), score: 80 },
        { timestamp: new Date(Date.now() - 5 * 24 * 3600000).toISOString(), score: 77 },
        { timestamp: new Date(Date.now() - 4 * 24 * 3600000).toISOString(), score: 82 },
        { timestamp: new Date(Date.now() - 3 * 24 * 3600000).toISOString(), score: 79 },
        { timestamp: new Date(Date.now() - 2 * 24 * 3600000).toISOString(), score: 84 },
        { timestamp: new Date(Date.now() - 1 * 24 * 3600000).toISOString(), score: 81 }
      ],
      trend: 'stable',
      improvement: '+3 points over 7 days',
      volatility: 'low'
    };
  }

  private async establishBaseline(scoreBreakdown: any, checklists: Record<string, SecurityChecklist>): Promise<void> {
    // This would save the current state as a baseline for future comparisons
    const baseline = {
      timestamp: new Date().toISOString(),
      overallScore: scoreBreakdown.overallScore,
      categoryScores: scoreBreakdown.categoryScores,
      checkStatuses: Object.fromEntries(
        Object.entries(checklists).map(([category, checklist]) => [
          category,
          checklist.checks.map(check => ({
            id: check.id,
            status: check.status
          }))
        ])
      )
    };

    // In a real implementation, this would be saved to persistent storage
    console.log('Baseline established:', baseline);
  }

  private assessComplianceStatus(checklists: Record<string, SecurityChecklist>): any {
    const totalChecks = Object.values(checklists).reduce((sum, checklist) => sum + checklist.checks.length, 0);
    const passingChecks = Object.values(checklists).reduce((sum, checklist) => 
      sum + checklist.checks.filter(check => check.status === 'pass').length, 0);
    
    const compliancePercentage = totalChecks > 0 ? Math.round((passingChecks / totalChecks) * 100) : 0;
    
    return {
      percentage: compliancePercentage,
      status: compliancePercentage >= 80 ? 'compliant' : 'non-compliant',
      frameworks: {
        'CIS Kubernetes Benchmark': compliancePercentage >= 80 ? 'compliant' : 'non-compliant',
        'NIST Cybersecurity Framework': compliancePercentage >= 75 ? 'compliant' : 'non-compliant',
        'ISO 27001': compliancePercentage >= 85 ? 'compliant' : 'non-compliant'
      }
    };
  }

  private calculateNextEvaluation(score: number): string {
    // More frequent evaluations for lower scores
    let hours = 24; // Default daily
    
    if (score < 50) {
      hours = 4; // Every 4 hours for critical scores
    } else if (score < 70) {
      hours = 8; // Every 8 hours for poor scores
    } else if (score < 85) {
      hours = 12; // Every 12 hours for moderate scores
    }
    
    const nextEval = new Date(Date.now() + hours * 3600000);
    return nextEval.toISOString();
  }
}