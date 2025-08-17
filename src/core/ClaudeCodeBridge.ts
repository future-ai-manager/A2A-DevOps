import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import { EventEmitter } from 'events';
import { ClaudeExecution, AgentContext } from './types';
import { ClaudeErrorClassifier } from './error/ClaudeErrorClassifier';
import { ClaudeErrorHandler } from './error/ClaudeErrorHandler';
import { ClaudeCodeError } from './error/types';

const execAsync = promisify(exec);

export interface ClaudeBridgeOptions {
  timeout?: number;
  maxRetries?: number;
  debug?: boolean;
}

export interface ClaudeResponse {
  success: boolean;
  data?: any;
  error?: string;
  executionTime: number;
  retries: number;
}

export class ClaudeCodeBridge extends EventEmitter {
  private timeout: number;
  private maxRetries: number;
  private debug: boolean;

  constructor(options: ClaudeBridgeOptions = {}) {
    super();
    this.timeout = options.timeout || 30000; // 30 seconds
    this.maxRetries = options.maxRetries || 3;
    this.debug = options.debug || false;
  }

  async checkClaudeCodeAvailability(): Promise<boolean> {
    try {
      console.log('Current process PATH:', process.env.PATH);
      const { stdout } = await execAsync('claude --version');
      this.emit('debug', `Claude Code version: ${stdout.trim()}`);
      return true;
    } catch (error) {
      this.emit('error', 'Claude Code CLI not found. Please install and authenticate Claude Code.');
      return false;
    }
  }

  async executeQuery(query: string, context?: AgentContext): Promise<ClaudeResponse> {
    const startTime = Date.now();
    let retries = 0;

    while (retries <= this.maxRetries) {
      try {
        const result = await this.runClaudeCommand(query, context);
        const executionTime = Date.now() - startTime;
        
        this.emit('queryExecuted', { query, executionTime, retries });
        
        return {
          success: true,
          data: result,
          executionTime,
          retries
        };
      } catch (error) {
        retries++;
        this.emit('retry', { query, attempt: retries, error });
        
        if (retries > this.maxRetries) {
          const executionTime = Date.now() - startTime;
          return {
            success: false,
            error: `Failed after ${retries} attempts: ${error instanceof Error ? error.message : 'Unknown error'}`,
            executionTime,
            retries
          };
        }

        // Exponential backoff
        await this.sleep(Math.pow(2, retries) * 1000);
      }
    }

    return {
      success: false,
      error: 'Max retries exceeded',
      executionTime: Date.now() - startTime,
      retries
    };
  }

  async routeToAgent(query: string, suggestedAgent?: string): Promise<ClaudeResponse> {
    const routingPrompt = this.buildRoutingPrompt(query, suggestedAgent);
    return await this.executeQuery(routingPrompt);
  }

  private async runClaudeCommand(query: string, context?: AgentContext): Promise<string> {
    return new Promise((resolve, reject) => {
      const args = ['--print'];
      if (this.debug) {
        args.push('--debug');
      }

      const claude = spawn('claude', args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: this.timeout
      });

      let stdout = '';
      let stderr = '';

      claude.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      claude.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      claude.on('close', (code) => {
        if (code === 0) {
          resolve(stdout.trim());
        } else {
          // 🎯 핵심: Claude Code 에러를 분류하고 사용자 친화적 메시지 생성
          const errorType = ClaudeErrorClassifier.classifyError(stderr, code);
          const userMessage = ClaudeErrorHandler.generateUserMessage(errorType, stderr);
          
          // Custom Error with user guidance
          const claudeError = new ClaudeCodeError(userMessage, {
            originalError: stderr,
            exitCode: code,
            errorType,
            recoverable: userMessage.recoverable
          });
          
          // 디버그 모드에서 원본 에러도 로깅
          if (this.debug) {
            this.emit('debug', `Claude Code Error Details: ${JSON.stringify({
              exitCode: code,
              stderr,
              errorType,
              recoverable: userMessage.recoverable
            }, null, 2)}`);
          }
          
          reject(claudeError);
        }
      });

      claude.on('error', (error) => {
        // Process spawn 에러도 분류 처리
        const errorType = ClaudeErrorClassifier.classifyError(error.message, -1);
        const userMessage = ClaudeErrorHandler.generateUserMessage(errorType, error.message);
        
        const claudeError = new ClaudeCodeError(userMessage, {
          originalError: error.message,
          exitCode: -1,
          errorType,
          recoverable: userMessage.recoverable
        });
        
        reject(claudeError);
      });

      // Send the query to Claude
      const fullPrompt = this.buildFullPrompt(query, context);
      claude.stdin.write(fullPrompt);
      claude.stdin.end();

      // Handle timeout
      setTimeout(() => {
        if (!claude.killed) {
          claude.kill('SIGTERM');
          reject(new Error('Claude Code execution timed out'));
        }
      }, this.timeout);
    });
  }

  private buildFullPrompt(query: string, context?: AgentContext): string {
    let prompt = `You are an intelligent DevOps agent router. Your job is to analyze queries and route them to appropriate specialized agents.

Available Agents:
1. Falco Security Agent - Runtime security monitoring, threat detection, container security
2. Prometheus Monitoring Agent - Metrics collection, performance monitoring, alerts
3. General DevOps Agent - General questions, best practices, documentation

`;

    if (context) {
      prompt += `Context:
- Intent: ${context.intent}
- Entities: ${context.entities.join(', ')}
- Confidence: ${context.confidence}

`;
    }

    prompt += `User Query: ${query}

Please analyze this query and provide:
1. Which agent should handle this query
2. Any preprocessing needed for the query
3. Expected response format
4. Confidence level in your routing decision

Format your response as JSON:
{
  "agent": "agent_name",
  "preprocessed_query": "modified query if needed",
  "response_format": "json|text|table",
  "confidence": 0.95,
  "reasoning": "explanation of routing decision"
}`;

    return prompt;
  }

  private buildRoutingPrompt(query: string, suggestedAgent?: string): string {
    let prompt = `You are an intelligent DevOps agent router. Analyze the following user query and determine the most appropriate agent to handle it.

User Query: "${query}"`;

    if (suggestedAgent) {
      prompt += `\nSuggested Agent: ${suggestedAgent}`;
    }

    prompt += `

Available Specialized Agents:

🔒 FALCO SECURITY AGENT
- Runtime security monitoring and threat detection
- Security log analysis and event correlation
- Container and Kubernetes security assessment
- Security compliance checking (CIS benchmarks, etc.)
- Vulnerability scanning and incident response
- Security audit and forensics
- Keywords: security, threat, logs, events, audit, vulnerability, intrusion, malware
- Languages: English, Korean (보안, 로그, 이벤트, 위협, 취약점)

📊 PROMETHEUS MONITORING AGENT  
- Metrics collection and performance monitoring
- System resource monitoring (CPU, memory, disk, network)
- Application performance metrics and SLI/SLO tracking
- Alert rule management and threshold monitoring
- PromQL queries and data visualization
- Health checks and uptime monitoring
- Keywords: metrics, performance, monitoring, alerts, cpu, memory, grafana
- Languages: English, Korean (모니터링, 메트릭, 성능, 알람)

🛠️ GENERAL DEVOPS AGENT
- DevOps best practices and guidance
- Installation and setup procedures
- Tool recommendations and architecture advice  
- General troubleshooting and documentation
- Process improvement and workflow optimization
- Educational content and tutorials
- Keywords: install, setup, how-to, best practice, guide, troubleshoot
- Languages: English, Korean (설치, 셋업, 가이드, 문제해결)

ROUTING GUIDELINES:
1. If the query mentions security, threats, logs, events, audit, or related terms → falco
2. If the query mentions metrics, performance, monitoring, alerts, or system resources → prometheus  
3. If the query is about installation, setup, best practices, or general guidance → general
4. Consider Korean keywords: 보안/로그/이벤트 → falco, 모니터링/성능 → prometheus, 설치/가이드 → general
5. Default to the most specific agent that matches the query intent

Please respond with ONLY the agent name: falco, prometheus, or general`;

    return prompt;
  }

  async executeWithAgent(agentName: string, query: string, parameters?: any): Promise<ClaudeResponse> {
    const agentPrompt = this.buildAgentPrompt(agentName, query, parameters);
    return await this.executeQuery(agentPrompt);
  }

  private buildAgentPrompt(agentName: string, query: string, parameters?: any): string {
    let prompt = `You are a specialized ${agentName} agent for DevOps operations.

`;

    switch (agentName.toLowerCase()) {
      case 'falco':
        prompt += `You specialize in:
- Runtime security monitoring
- Threat detection and analysis
- Container security assessment
- Security compliance checking
- Falco rule management

Security Checklist Categories:
- File System Security (write_below_etc, write_below_usr, etc.)
- Process and Execution Security (spawned_process_in_container, etc.)
- Network Security (unexpected_network_connection, etc.)
- Privilege Escalation (sudo_without_tty, setuid_setgid, etc.)
- Container Security (container_drift, container_escape_attempt, etc.)
- Kubernetes-Specific Security (k8s_api_connection, rbac_violation, etc.)

`;
        break;

      case 'prometheus':
        prompt += `You specialize in:
- Metrics collection and analysis
- Performance monitoring
- Alert rule creation and management
- PromQL queries
- System resource monitoring
- Application performance metrics

`;
        break;

      case 'general':
        prompt += `You provide:
- DevOps best practices
- Tool recommendations
- Architecture guidance
- Process improvement suggestions
- General troubleshooting help

`;
        break;
    }

    if (parameters) {
      prompt += `Parameters: ${JSON.stringify(parameters, null, 2)}

`;
    }

    prompt += `User Query: ${query}

Please provide a detailed, actionable response based on your specialization.`;

    return prompt;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async testConnection(): Promise<boolean> {
    try {
      const response = await this.executeQuery('Hello, are you working?');
      return response.success;
    } catch (error) {
      return false;
    }
  }
}