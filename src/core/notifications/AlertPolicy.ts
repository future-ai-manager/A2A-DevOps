import { SecurityEvent } from '../types';
import { AlertDecision, AlertRule } from './types';

export class AlertPolicy {
  private rules: AlertRule[] = [
    {
      name: 'Critical Events',
      condition: (event: SecurityEvent) => event.severity === 'critical',
      channels: ['slack', 'pagerduty'],
      throttleDuration: 5 * 60 * 1000, // 5 minutes
      priority: 1
    },
    {
      name: 'High Severity Events',
      condition: (event: SecurityEvent) => event.severity === 'high',
      channels: ['slack'],
      throttleDuration: 10 * 60 * 1000, // 10 minutes
      priority: 2
    },
    {
      name: 'Privilege Escalation',
      condition: (event: SecurityEvent) => 
        event.rule.toLowerCase().includes('privilege') ||
        event.rule.toLowerCase().includes('escalation') ||
        event.rule.toLowerCase().includes('sudo'),
      channels: ['slack', 'pagerduty'],
      throttleDuration: 2 * 60 * 1000, // 2 minutes
      priority: 1
    },
    {
      name: 'Sensitive File Access',
      condition: (event: SecurityEvent) => 
        event.rule.toLowerCase().includes('sensitive') ||
        event.rule.toLowerCase().includes('passwd') ||
        event.rule.toLowerCase().includes('shadow') ||
        event.rule.toLowerCase().includes('/etc/'),
      channels: ['slack'],
      throttleDuration: 15 * 60 * 1000, // 15 minutes
      priority: 2
    },
    {
      name: 'Container Breakout',
      condition: (event: SecurityEvent) => 
        event.rule.toLowerCase().includes('container') ||
        event.rule.toLowerCase().includes('docker') ||
        event.rule.toLowerCase().includes('kubernetes'),
      channels: ['slack', 'pagerduty'],
      throttleDuration: 1 * 60 * 1000, // 1 minute
      priority: 1
    },
    {
      name: 'Network Anomalies',
      condition: (event: SecurityEvent) => 
        event.rule.toLowerCase().includes('network') ||
        event.rule.toLowerCase().includes('connection') ||
        event.rule.toLowerCase().includes('port'),
      channels: ['slack'],
      throttleDuration: 20 * 60 * 1000, // 20 minutes
      priority: 3
    },
    {
      name: 'Process Anomalies',
      condition: (event: SecurityEvent) => 
        event.rule.toLowerCase().includes('process') ||
        event.rule.toLowerCase().includes('binary') ||
        event.rule.toLowerCase().includes('execution'),
      channels: ['slack'],
      throttleDuration: 30 * 60 * 1000, // 30 minutes
      priority: 3
    },
    {
      name: 'Medium Severity Events',
      condition: (event: SecurityEvent) => event.severity === 'medium',
      channels: ['slack'],
      throttleDuration: 30 * 60 * 1000, // 30 minutes
      priority: 4
    }
  ];

  shouldAlert(event: SecurityEvent): AlertDecision {
    // Find the first matching rule with highest priority
    const matchingRules = this.rules
      .filter(rule => rule.condition(event))
      .sort((a, b) => (a.priority || 99) - (b.priority || 99));

    if (matchingRules.length === 0) {
      // Default rule for unmatched events
      if (event.severity === 'low') {
        return { send: false };
      }
      
      return {
        send: true,
        channels: ['slack'],
        throttleKey: `default-${event.rule}-${event.source}`,
        throttleDuration: 60 * 60 * 1000 // 1 hour
      };
    }

    const rule = matchingRules[0];
    return {
      send: true,
      channels: rule.channels,
      throttleKey: `${rule.name}-${event.rule}-${event.source}`,
      throttleDuration: rule.throttleDuration
    };
  }

  addRule(rule: AlertRule): void {
    this.rules.push(rule);
    this.sortRules();
  }

  removeRule(name: string): boolean {
    const index = this.rules.findIndex(rule => rule.name === name);
    if (index !== -1) {
      this.rules.splice(index, 1);
      return true;
    }
    return false;
  }

  updateRule(name: string, updates: Partial<AlertRule>): boolean {
    const rule = this.rules.find(rule => rule.name === name);
    if (rule) {
      Object.assign(rule, updates);
      this.sortRules();
      return true;
    }
    return false;
  }

  getRules(): AlertRule[] {
    return [...this.rules];
  }

  private sortRules(): void {
    this.rules.sort((a, b) => (a.priority || 99) - (b.priority || 99));
  }

  // Test a rule against an event
  testRule(ruleName: string, event: SecurityEvent): AlertDecision | null {
    const rule = this.rules.find(r => r.name === ruleName);
    if (!rule) return null;

    if (rule.condition(event)) {
      return {
        send: true,
        channels: rule.channels,
        throttleKey: `${rule.name}-${event.rule}-${event.source}`,
        throttleDuration: rule.throttleDuration
      };
    }

    return { send: false };
  }

  // Get statistics about rule usage
  getRuleStats(): Record<string, { name: string; priority: number }> {
    const stats: Record<string, { name: string; priority: number }> = {};
    
    for (const rule of this.rules) {
      stats[rule.name] = {
        name: rule.name,
        priority: rule.priority || 99
      };
    }

    return stats;
  }
}