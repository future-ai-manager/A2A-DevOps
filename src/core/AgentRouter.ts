import { EventEmitter } from 'events';
import { AgentContext, AgentCapability } from './types';
import { ClaudeCodeBridge } from './ClaudeCodeBridge';

export interface RoutingResult {
  agent: string;
  confidence: number;
  reasoning: string;
  preprocessedQuery?: string;
  parameters?: any;
}

export interface RoutingHistory {
  query: string;
  agent: string;
  confidence: number;
  success: boolean;
  timestamp: number;
  executionTime: number;
}

export class AgentRouter extends EventEmitter {
  private claudeBridge: ClaudeCodeBridge;
  private agentCapabilities: Map<string, AgentCapability[]> = new Map();
  private routingHistory: RoutingHistory[] = [];
  private maxHistorySize = 1000;

  // Keyword-based routing rules for fast initial routing
  private routingRules = {
    installation: {
      keywords: [
        'install', 'setup', 'deploy', 'configure', '설치', '셋업', '배포', '구성',
        'helm install', 'kubectl apply', 'docker run', 'deployment'
      ],
      agent: 'general',
      confidence: 0.95
    },
    security: {
      keywords: [
        'security', 'threat', 'vulnerability', 'container security',
        'runtime security', 'malware', 'intrusion', 'privilege escalation',
        'suspicious activity', 'security audit', 'compliance', 'cis benchmark',
        'rbac', 'network security', 'file integrity', 'container escape',
        '보안', '위협', '취약점', '침입', '악성코드', '로그', '이벤트', '감사',
        'log', 'logs', 'event', 'events', 'audit', '최근', 'recent', 'latest'
      ],
      agent: 'falco',
      confidence: 0.9
    },
    monitoring: {
      keywords: [
        'metrics', 'monitor', 'grafana', 'alert', 'performance',
        'cpu usage', 'memory usage', 'disk usage', 'network usage', 'uptime',
        'latency', 'throughput', 'error rate', 'slo', 'sli', 'dashboard',
        'promql', 'query metrics', 'system health'
      ],
      agent: 'prometheus',
      confidence: 0.8
    },
    general: {
      keywords: [
        'best practice', 'how to', 'what is', 'explain', 'documentation',
        'tutorial', 'guide', 'troubleshoot',
        'devops', 'kubernetes', 'docker', 'helm', 'ci/cd', 'gitops'
      ],
      agent: 'general',
      confidence: 0.7
    }
  };

  constructor(claudeBridge: ClaudeCodeBridge) {
    super();
    this.claudeBridge = claudeBridge;
    this.initializeDefaultCapabilities();
  }

  private initializeDefaultCapabilities(): void {
    // Falco Security Agent capabilities
    this.agentCapabilities.set('falco', [
      {
        domain: 'security',
        description: 'Runtime security monitoring and threat detection',
        keywords: ['security', 'threat', 'vulnerability', 'malware', 'intrusion'],
        priority: 1
      },
      {
        domain: 'compliance',
        description: 'Security compliance and audit checks',
        keywords: ['compliance', 'audit', 'cis', 'benchmark', 'policy'],
        priority: 2
      },
      {
        domain: 'container_security',
        description: 'Container and Kubernetes security',
        keywords: ['container', 'kubernetes', 'pod', 'namespace', 'rbac'],
        priority: 1
      }
    ]);

    // Prometheus Monitoring Agent capabilities
    this.agentCapabilities.set('prometheus', [
      {
        domain: 'metrics',
        description: 'System and application metrics collection',
        keywords: ['metrics', 'cpu', 'memory', 'disk', 'network', 'performance'],
        priority: 1
      },
      {
        domain: 'alerting',
        description: 'Alert rule management and evaluation',
        keywords: ['alert', 'notification', 'threshold', 'slo', 'sli'],
        priority: 2
      },
      {
        domain: 'monitoring',
        description: 'System health monitoring and analysis',
        keywords: ['monitor', 'health', 'uptime', 'availability', 'dashboard'],
        priority: 1
      }
    ]);

    // General DevOps Agent capabilities
    this.agentCapabilities.set('general', [
      {
        domain: 'guidance',
        description: 'DevOps best practices and guidance',
        keywords: ['best practice', 'guide', 'tutorial', 'how to', 'setup'],
        priority: 3
      },
      {
        domain: 'troubleshooting',
        description: 'General troubleshooting and problem solving',
        keywords: ['troubleshoot', 'debug', 'error', 'fix', 'problem'],
        priority: 2
      }
    ]);
  }

  async routeQuery(query: string, forceAgent?: string): Promise<RoutingResult> {
    const startTime = Date.now();
    
    // If force agent is specified, use it directly
    if (forceAgent && this.agentCapabilities.has(forceAgent)) {
      return {
        agent: forceAgent,
        confidence: 1.0,
        reasoning: `Forced routing to ${forceAgent} agent`
      };
    }

    try {
      // Step 1: Primary - Use Claude Code for intelligent routing
      console.log(`🔍 Attempting Claude routing for query: "${query}"`);
      const claudeResult = await this.performClaudeRouting(query);
      console.log(`📊 Claude routing result:`, { agent: claudeResult.agent, confidence: claudeResult.confidence, reasoning: claudeResult.reasoning });
      
      // Step 2: If Claude routing has good confidence, use it directly
      if (claudeResult.confidence >= 0.7) {
        console.log(`✅ Using Claude routing (confidence: ${claudeResult.confidence})`);
        this.recordRoutingHistory(query, claudeResult, startTime, true);
        this.emit('routingCompleted', { query, result: claudeResult });
        return claudeResult;
      }

      // Step 3: Secondary - Get keyword-based routing for comparison
      const keywordResult = this.performKeywordRouting(query);
      
      // Step 4: Combine results for final decision
      const finalResult = this.combineRoutingResults(keywordResult, claudeResult);
      
      this.recordRoutingHistory(query, finalResult, startTime, true);
      this.emit('routingCompleted', { query, result: finalResult });
      
      return finalResult;

    } catch (error) {
      // Fallback to keyword routing on Claude failure
      console.log(`❌ Claude routing failed:`, error);
      this.emit('routingError', { query, error });
      const keywordResult = this.performKeywordRouting(query);
      console.log(`📋 Fallback to keyword routing:`, { agent: keywordResult.agent, confidence: keywordResult.confidence, reasoning: keywordResult.reasoning });
      
      const fallbackResult = keywordResult.confidence > 0 ? keywordResult : {
        agent: 'general',
        confidence: 0.4,
        reasoning: 'Fallback to general agent due to Claude routing error'
      };
      
      this.recordRoutingHistory(query, fallbackResult, startTime, false);
      return fallbackResult;
    }
  }

  private performKeywordRouting(query: string): RoutingResult {
    const normalizedQuery = query.toLowerCase();
    let bestMatch = {
      agent: 'general',
      confidence: 0.3,
      reasoning: 'Default fallback to general agent',
      score: 0
    };

    for (const [category, rules] of Object.entries(this.routingRules)) {
      let matchCount = 0;
      const matchedKeywords: string[] = [];

      for (const keyword of rules.keywords) {
        if (normalizedQuery.includes(keyword.toLowerCase())) {
          matchCount++;
          matchedKeywords.push(keyword);
        }
      }

      if (matchCount > 0) {
        // Calculate confidence based on keyword matches and base confidence
        const keywordConfidence = Math.min(0.95, rules.confidence + (matchCount * 0.05));
        const score = matchCount * rules.confidence;

        if (score > bestMatch.score) {
          bestMatch = {
            agent: rules.agent,
            confidence: keywordConfidence,
            reasoning: `Matched ${matchCount} keywords: ${matchedKeywords.join(', ')}`,
            score
          };
        }
      }
    }

    return {
      agent: bestMatch.agent,
      confidence: bestMatch.confidence,
      reasoning: bestMatch.reasoning
    };
  }

  private async performClaudeRouting(query: string): Promise<RoutingResult> {
    try {
      const response = await this.claudeBridge.routeToAgent(query);
      
      if (!response.success) {
        throw new Error(response.error || 'Claude routing failed');
      }

      // Try to parse JSON response first
      let routingData: any;
      try {
        routingData = JSON.parse(response.data);
      } catch {
        // If not JSON, extract agent name from text response
        const responseText = response.data.toLowerCase().trim();
        
        // Look for agent names at the start/end of response or on their own line
        let detectedAgent = 'general';
        let confidence = 0.8;
        let reasoning = 'Extracted from Claude text response';
        
        if (responseText === 'falco' || responseText.endsWith('falco') || responseText.startsWith('falco')) {
          detectedAgent = 'falco';
          confidence = 0.9;
        } else if (responseText === 'prometheus' || responseText.endsWith('prometheus') || responseText.startsWith('prometheus')) {
          detectedAgent = 'prometheus';
          confidence = 0.9;
        } else if (responseText === 'general' || responseText.endsWith('general') || responseText.startsWith('general')) {
          detectedAgent = 'general';
          confidence = 0.9;
        } else {
          // Fallback pattern matching
          const agentMatch = response.data.match(/\b(falco|prometheus|general)\b/i);
          if (agentMatch) {
            detectedAgent = agentMatch[1].toLowerCase();
            confidence = 0.7;
          } else {
            // If no agent found, make intelligent guess based on response content
            const responseData = response.data.toLowerCase();
            if (responseData.includes('security') || responseData.includes('threat') || responseData.includes('log')) {
              detectedAgent = 'falco';
              reasoning = 'Inferred from security-related content in response';
            } else if (responseData.includes('metric') || responseData.includes('monitor') || responseData.includes('performance')) {
              detectedAgent = 'prometheus';
              reasoning = 'Inferred from monitoring-related content in response';
            }
            confidence = 0.6;
          }
        }
        
        routingData = {
          agent: detectedAgent,
          confidence,
          reasoning
        };
      }

      return {
        agent: routingData.agent || 'general',
        confidence: Math.min(0.95, routingData.confidence || 0.7),
        reasoning: routingData.reasoning || 'Claude Code routing decision',
        preprocessedQuery: routingData.preprocessed_query,
        parameters: routingData.parameters
      };

    } catch (error) {
      throw new Error(`Claude routing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private combineRoutingResults(keywordResult: RoutingResult, claudeResult: RoutingResult): RoutingResult {
    // If both results agree on the agent, increase confidence
    if (keywordResult.agent === claudeResult.agent) {
      return {
        agent: keywordResult.agent,
        confidence: Math.min(0.98, (keywordResult.confidence + claudeResult.confidence) / 2 + 0.1),
        reasoning: `Both keyword and Claude routing agree on ${keywordResult.agent}`,
        preprocessedQuery: claudeResult.preprocessedQuery,
        parameters: claudeResult.parameters
      };
    }

    // If they disagree, use the one with higher confidence
    if (claudeResult.confidence > keywordResult.confidence) {
      return {
        ...claudeResult,
        reasoning: `Claude routing (${claudeResult.confidence.toFixed(2)}) overrode keyword routing (${keywordResult.confidence.toFixed(2)})`
      };
    } else {
      return {
        ...keywordResult,
        reasoning: `Keyword routing (${keywordResult.confidence.toFixed(2)}) overrode Claude routing (${claudeResult.confidence.toFixed(2)})`
      };
    }
  }

  private recordRoutingHistory(query: string, result: RoutingResult, startTime: number, success: boolean): void {
    const historyEntry: RoutingHistory = {
      query,
      agent: result.agent,
      confidence: result.confidence,
      success,
      timestamp: startTime,
      executionTime: Date.now() - startTime
    };

    this.routingHistory.unshift(historyEntry);

    // Maintain history size limit
    if (this.routingHistory.length > this.maxHistorySize) {
      this.routingHistory = this.routingHistory.slice(0, this.maxHistorySize);
    }
  }

  getRoutingHistory(limit: number = 50): RoutingHistory[] {
    return this.routingHistory.slice(0, limit);
  }

  getRoutingStats(): any {
    if (this.routingHistory.length === 0) {
      return {
        totalQueries: 0,
        successRate: 0,
        averageExecutionTime: 0,
        agentDistribution: {},
        averageConfidence: 0
      };
    }

    const totalQueries = this.routingHistory.length;
    const successfulQueries = this.routingHistory.filter(entry => entry.success).length;
    const successRate = successfulQueries / totalQueries;

    const averageExecutionTime = this.routingHistory.reduce((sum, entry) => sum + entry.executionTime, 0) / totalQueries;
    
    const agentCounts: Record<string, number> = {};
    let totalConfidence = 0;

    for (const entry of this.routingHistory) {
      agentCounts[entry.agent] = (agentCounts[entry.agent] || 0) + 1;
      totalConfidence += entry.confidence;
    }

    const agentDistribution: Record<string, number> = {};
    for (const [agent, count] of Object.entries(agentCounts)) {
      agentDistribution[agent] = count / totalQueries;
    }

    return {
      totalQueries,
      successRate,
      averageExecutionTime,
      agentDistribution,
      averageConfidence: totalConfidence / totalQueries
    };
  }

  registerAgent(name: string, capabilities: AgentCapability[]): void {
    this.agentCapabilities.set(name, capabilities);
    this.emit('agentRegistered', { name, capabilities });
  }

  getRegisteredAgents(): string[] {
    return Array.from(this.agentCapabilities.keys());
  }

  getAgentCapabilities(agentName: string): AgentCapability[] {
    return this.agentCapabilities.get(agentName) || [];
  }

  async optimizeRouting(): Promise<void> {
    // Analyze routing history to improve keyword rules
    const stats = this.getRoutingStats();
    
    // Find patterns in failed routings
    const failedRoutings = this.routingHistory.filter(entry => !entry.success);
    
    if (failedRoutings.length > 0) {
      this.emit('routingOptimization', {
        totalFailures: failedRoutings.length,
        suggestions: 'Consider updating keyword rules or agent capabilities'
      });
    }
  }
}