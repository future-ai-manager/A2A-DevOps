export interface MCPMessage {
  jsonrpc: "2.0";
  method: string;
  params?: any;
  id?: string | number;
}

export interface MCPResponse {
  jsonrpc: "2.0";
  result?: any;
  error?: MCPError;
  id: string | number;
}

export interface MCPError {
  code: number;
  message: string;
  data?: any;
}

export interface Tool {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, any>;
    required?: string[];
  };
}

export interface ToolCall {
  name: string;
  params: any;
}

export interface ToolResult {
  success: boolean;
  data?: any;
  error?: string;
}

export interface AgentCapability {
  domain: string;
  description: string;
  keywords: string[];
  priority: number;
}

export interface AgentContext {
  query: string;
  intent: string;
  entities: string[];
  confidence: number;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  severity: "low" | "medium" | "high" | "critical";
  rule: string;
  description: string;
  source: string;
  tags: string[];
  metadata: Record<string, any>;
}

export interface SecurityChecklist {
  category: string;
  checks: SecurityCheck[];
  score: number;
  status: "passing" | "failing" | "warning";
}

export interface SecurityCheck {
  id: string;
  name: string;
  description: string;
  status: "pass" | "fail" | "warning" | "unknown";
  rule?: string;
  details?: string;
}

export interface MonitoringMetric {
  name: string;
  value: number;
  timestamp: number;
  labels: Record<string, string>;
  unit?: string;
}

export interface AlertRule {
  name: string;
  query: string;
  severity: string;
  threshold: number;
  duration: string;
  description: string;
}

export interface ClaudeExecution {
  command: string;
  args: string[];
  env?: NodeJS.ProcessEnv;
  timeout?: number;
}

export interface ErrorResponse {
  code: string;
  message: string;
  details?: any;
  suggestion?: string;
  documentation?: string;
}

export interface Configuration {
  claudeCode: {
    timeout: number;
    maxRetries: number;
  };
  monitoring: {
    prometheusUrl: string;
    falcoSocket: string;
  };
  notifications: {
    slack: {
      enabled: boolean;
      webhookUrl: string;
      channel?: string;
    };
    pagerduty: {
      enabled: boolean;
      apiKey: string;
    };
  };
  debug: boolean;
  logLevel: string;
}

export interface ServerConfig {
  name: string;
  command: string;
  args: string[];
  domain: string;
  capabilities: AgentCapability[];
  healthCheck?: {
    endpoint: string;
    interval: number;
    timeout: number;
  };
}