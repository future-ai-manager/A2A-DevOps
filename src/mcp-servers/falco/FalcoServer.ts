import { MCPServer } from '@mcp-servers/base/MCPServer';
import { AgentCapability, SecurityEvent } from '@core/types';
import { DetectThreatsTool } from './tools/detect-threats';
import { CheckRulesTool } from './tools/check-rules';
import { SecurityScoreTool } from './tools/security-score';
import { SecurityTestValidationTool } from './tools/security-test-validation';
import { ConfigureNotificationsTool } from './tools/configure-notifications';
import { EasyConfigTool } from './tools/easy-config';
import { DeployMonitoringStackTool } from './tools/deploy-monitoring-stack';
import { FalcoClient, FalcoEvent } from '@core/FalcoClient';
import { KubernetesClient, ClusterInfo } from '@core/KubernetesClient';
import { NotificationManager } from '@core/notifications/NotificationManager';
import { ConfigManager } from '../../cli/utils/config';
import { randomUUID } from 'crypto';

export class FalcoServer extends MCPServer {
  readonly name = 'falco';
  private falcoClient!: FalcoClient;
  private kubernetesClient!: KubernetesClient;
  private notificationManager!: NotificationManager;
  private configManager = ConfigManager.getInstance();
  private realTimeEvents: FalcoEvent[] = [];
  private maxStoredEvents: number = 1000;

  readonly capabilities: AgentCapability[] = [
    {
      domain: 'security',
      description: 'Runtime security monitoring and threat detection',
      keywords: [
        'security', 'threat', 'vulnerability', 'malware', 'intrusion',
        'falco', 'runtime security', 'container security', 'suspicious activity'
      ],
      priority: 1
    },
    {
      domain: 'compliance',
      description: 'Security compliance and audit checks',
      keywords: [
        'compliance', 'audit', 'cis benchmark', 'security policy',
        'governance', 'risk assessment', 'security posture'
      ],
      priority: 2
    },
    {
      domain: 'incident_response',
      description: 'Security incident detection and response',
      keywords: [
        'incident', 'alert', 'security event', 'forensics',
        'investigation', 'breach detection', 'anomaly detection'
      ],
      priority: 1
    }
  ];

  protected initializeTools(): void {
    // Register all Falco-specific tools
    this.registerTool(new DetectThreatsTool());
    this.registerTool(new CheckRulesTool());
    this.registerTool(new SecurityScoreTool());
    this.registerTool(new SecurityTestValidationTool());
    this.registerTool(new ConfigureNotificationsTool());
    this.registerTool(new EasyConfigTool());
    this.registerTool(new DeployMonitoringStackTool());
  }

  protected async onStart(): Promise<void> {
    try {
      // Initialize clients
      this.falcoClient = new FalcoClient();
      this.kubernetesClient = new KubernetesClient();

      // Initialize notification manager
      await this.initializeNotificationManager();

      // Setup event listeners
      this.setupFalcoEventListeners();
      this.setupKubernetesEventListeners();

      // Attempt Falco connection
      const falcoConnected = await this.falcoClient.connect();
      if (!falcoConnected) {
        console.warn('⚠️  Falco 연결 실패. 설치 및 설정을 확인하세요.');
        this.emit('warning', {
          server: this.name,
          message: 'Falco 런타임이 감지되지 않았습니다. 전체 기능을 위해 Falco를 설치하세요.'
        });
      } else {
        console.log('✅ Falco 실시간 연결 성공');
        this.emit('info', {
          server: this.name,
          message: 'Falco 실시간 이벤트 스트림 연결됨'
        });
      }

      // Attempt Kubernetes connection
      const k8sConnected = await this.kubernetesClient.connect();
      if (!k8sConnected) {
        console.warn('⚠️  Kubernetes 연결 실패. kubeconfig를 확인하세요.');
        this.emit('warning', {
          server: this.name,
          message: 'Kubernetes 클러스터에 연결할 수 없습니다. kubeconfig를 확인하세요.'
        });
      } else {
        const status = this.kubernetesClient.getConnectionStatus();
        console.log(`✅ Kubernetes 연결 성공: ${status.config?.server} (${status.config?.context})`);
        this.emit('info', {
          server: this.name,
          message: `Kubernetes 클러스터 연결됨: ${status.config?.context}`
        });
      }

      console.log(`🔒 Falco MCP Server started successfully on port ${this.port || 'default'}`);
      
    } catch (error) {
      console.error(`❌ Failed to start Falco MCP Server: ${error}`);
      throw error;
    }
  }

  protected async onStop(): Promise<void> {
    try {
      // Cleanup connections
      if (this.falcoClient) {
        await this.falcoClient.disconnect();
      }
      
      if (this.kubernetesClient) {
        await this.kubernetesClient.disconnect();
      }

      if (this.notificationManager) {
        this.notificationManager.stop();
      }
      
      console.log('🔒 Falco MCP Server stopped successfully');
    } catch (error) {
      console.error(`❌ Error stopping Falco MCP Server: ${error}`);
      throw error;
    }
  }

  /**
   * Falco 이벤트 리스너 설정
   */
  private setupFalcoEventListeners(): void {
    this.falcoClient.on('connected', (info) => {
      console.log(`🔗 Falco 연결됨: ${info.type} (${info.port || info.path || 'unknown'})`);
      this.emit('info', {
        server: this.name,
        message: `Falco 연결 성공: ${info.type}`
      });
    });

    this.falcoClient.on('event', (event: FalcoEvent) => {
      // 실시간 이벤트 저장 (최대 개수 제한)
      this.realTimeEvents.unshift(event);
      if (this.realTimeEvents.length > this.maxStoredEvents) {
        this.realTimeEvents = this.realTimeEvents.slice(0, this.maxStoredEvents);
      }

      // 중요한 이벤트는 즉시 알림
      if (event.priority === 'CRITICAL' || event.priority === 'ERROR') {
        this.emit('criticalEvent', event);
        // Send notification
        this.handleCriticalEvent(event);
      }

      // 디버그 로그
      if (process.env.A2A_DEBUG === 'true') {
        console.log(`🚨 Falco 이벤트: ${event.rule} (${event.priority})`);
      }
    });

    this.falcoClient.on('error', (error) => {
      console.error(`❌ Falco 클라이언트 오류: ${error}`);
      this.emit('error', {
        server: this.name,
        message: `Falco 연결 오류: ${error}`
      });
    });

    this.falcoClient.on('disconnected', () => {
      console.warn('⚠️  Falco 연결 해제됨');
      this.emit('warning', {
        server: this.name,
        message: 'Falco 연결이 해제되었습니다'
      });
    });
  }

  /**
   * Kubernetes 이벤트 리스너 설정
   */
  private setupKubernetesEventListeners(): void {
    this.kubernetesClient.on('connected', (info) => {
      console.log(`🔗 Kubernetes 연결됨: ${info.server} (컨텍스트: ${info.context})`);
      this.emit('info', {
        server: this.name,
        message: `Kubernetes 클러스터 연결: ${info.context}`
      });
    });

    this.kubernetesClient.on('clusterInfo', (clusterInfo: ClusterInfo) => {
      console.log(`📊 클러스터 정보: ${clusterInfo.nodeCount}개 노드, ${clusterInfo.namespaces.length}개 네임스페이스`);
    });

    this.kubernetesClient.on('podEvent', (event) => {
      if (process.env.A2A_DEBUG === 'true') {
        console.log(`🔄 Pod 이벤트: ${event.object?.metadata?.name} (${event.namespace})`);
      }
    });

    this.kubernetesClient.on('error', (error) => {
      console.error(`❌ Kubernetes 클라이언트 오류: ${error}`);
      this.emit('error', {
        server: this.name,
        message: `Kubernetes 연결 오류: ${error}`
      });
    });

    this.kubernetesClient.on('disconnected', () => {
      console.warn('⚠️  Kubernetes 연결 해제됨');
      this.emit('warning', {
        server: this.name,
        message: 'Kubernetes 연결이 해제되었습니다'
      });
    });
  }

  /**
   * 실시간 Falco 이벤트 가져오기
   */
  getRealtimeEvents(limit: number = 100): FalcoEvent[] {
    return this.realTimeEvents.slice(0, limit);
  }

  /**
   * 특정 룰의 이벤트 필터링
   */
  getEventsByRule(ruleName: string, limit: number = 50): FalcoEvent[] {
    return this.realTimeEvents
      .filter(event => event.rule.toLowerCase().includes(ruleName.toLowerCase()))
      .slice(0, limit);
  }

  /**
   * 우선순위별 이벤트 필터링
   */
  getEventsByPriority(priority: string, limit: number = 50): FalcoEvent[] {
    return this.realTimeEvents
      .filter(event => event.priority === priority.toUpperCase())
      .slice(0, limit);
  }

  /**
   * Kubernetes 클러스터 상태 가져오기
   */
  async getKubernetesStatus(): Promise<any> {
    if (!this.kubernetesClient) {
      return { connected: false, error: 'Kubernetes client not initialized' };
    }

    const status = this.kubernetesClient.getConnectionStatus();
    if (!status.connected) {
      return { connected: false, clusters: [] };
    }

    try {
      const healthCheck = await this.kubernetesClient.healthCheck();
      const permissions = await this.kubernetesClient.checkPermissions();
      
      return {
        connected: true,
        config: status.config,
        clusters: status.clusters,
        currentContext: status.currentContext,
        health: healthCheck,
        permissions
      };
    } catch (error) {
      return {
        connected: status.connected,
        config: status.config,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // Public methods for external access
  async getSecurityStatus(): Promise<any> {
    try {
      const securityScoreTool = this.tools.get('security_score');
      if (!securityScoreTool) {
        throw new Error('Security score tool not available');
      }

      const result = await securityScoreTool.execute({
        timeRange: '24h',
        includeCategories: ['filesystem', 'process', 'network', 'privilege', 'container', 'kubernetes']
      });

      if (!result.success) {
        throw new Error(result.error || 'Failed to get security status');
      }

      return result.data;

    } catch (error) {
      throw new Error(`Failed to get security status: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async detectCurrentThreats(): Promise<any> {
    try {
      const detectThreatsTool = this.tools.get('detect_threats');
      if (!detectThreatsTool) {
        throw new Error('Detect threats tool not available');
      }

      const result = await detectThreatsTool.execute({
        timeRange: '1h',
        severity: 'medium',
        maxEvents: 50
      });

      if (!result.success) {
        throw new Error(result.error || 'Failed to detect threats');
      }

      return result.data;

    } catch (error) {
      throw new Error(`Failed to detect threats: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async validateSecurityRules(): Promise<any> {
    try {
      const checkRulesTool = this.tools.get('check_rules');
      if (!checkRulesTool) {
        throw new Error('Check rules tool not available');
      }

      const result = await checkRulesTool.execute({
        action: 'validate'
      });

      if (!result.success) {
        throw new Error(result.error || 'Failed to validate rules');
      }

      return result.data;

    } catch (error) {
      throw new Error(`Failed to validate rules: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Health check method
  async healthCheck(): Promise<{ status: string; details: any }> {
    try {
      const falcoStatus = this.falcoClient ? this.falcoClient.getConnectionStatus() : { connected: false, connection: null };
      const k8sStatus = this.kubernetesClient ? this.kubernetesClient.getConnectionStatus() : { connected: false, config: null, clusters: [], currentContext: null };
      const toolsCount = this.tools.size;
      
      let overallStatus = 'healthy';
      
      if (!falcoStatus.connected && !k8sStatus.connected) {
        overallStatus = 'unhealthy';
      } else if (!falcoStatus.connected || !k8sStatus.connected) {
        overallStatus = 'degraded';
      }
      
      const status = {
        status: overallStatus,
        details: {
          falco: {
            connected: falcoStatus.connected,
            connectionType: falcoStatus.connection?.type || 'none',
            endpoint: falcoStatus.connection?.endpoint || 'none',
            realtimeEvents: this.realTimeEvents.length
          },
          kubernetes: {
            connected: k8sStatus.connected,
            server: k8sStatus.config?.server || 'none',
            context: k8sStatus.currentContext || 'none',
            clusters: k8sStatus.clusters.length
          },
          server: {
            registeredTools: toolsCount,
            capabilities: this.capabilities.length,
            serverStatus: this.status
          },
          lastHealthCheck: new Date().toISOString()
        }
      };

      // 권장 사항 추가
      const recommendations: string[] = [];
      if (!falcoStatus.connected) {
        recommendations.push('Falco를 설치하고 구성하여 전체 보안 모니터링 기능을 활성화하세요.');
      }
      if (!k8sStatus.connected) {
        recommendations.push('kubeconfig를 구성하여 Kubernetes 클러스터 모니터링을 활성화하세요.');
      }
      
      if (recommendations.length > 0) {
        (status.details as any).recommendations = recommendations;
      }

      return status;

    } catch (error) {
      return {
        status: 'unhealthy',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error',
          lastHealthCheck: new Date().toISOString()
        }
      };
    }
  }

  // Method to get tool usage statistics
  getToolUsageStats(): any {
    const stats = {
      totalTools: this.tools.size,
      toolList: Array.from(this.tools.keys()),
      capabilities: this.capabilities.map(cap => ({
        domain: cap.domain,
        priority: cap.priority,
        keywordCount: cap.keywords.length
      })),
      serverUptime: this.isRunning ? 'running' : 'stopped'
    };

    return stats;
  }

  // Initialize notification manager
  private async initializeNotificationManager(): Promise<void> {
    try {
      const config = await this.configManager.getConfig();
      if (config.notifications) {
        this.notificationManager = new NotificationManager(config.notifications);
        this.notificationManager.startCleanup();
        console.log('✅ Notification manager initialized');
      } else {
        console.log('⚠️  No notification configuration found');
      }
    } catch (error) {
      console.error(`❌ Failed to initialize notification manager: ${error}`);
    }
  }

  // Handle critical events and send notifications
  private async handleCriticalEvent(event: FalcoEvent): Promise<void> {
    if (!this.notificationManager) {
      return;
    }

    try {
      const securityEvent: SecurityEvent = {
        id: this.generateSecurityEventId(event),
        timestamp: new Date().toISOString(),
        severity: this.mapPriorityToSeverity(event.priority),
        rule: event.rule,
        description: event.output || 'Security event detected',
        source: 'falco',
        tags: event.tags || [],
        metadata: {
          priority: event.priority,
          time: event.time,
          output_fields: event.output_fields || {},
          hostname: event.hostname,
          source: event.source,
          falco_event: event
        }
      };

      await this.notificationManager.sendAlert(securityEvent);
      console.log(`📧 Notification sent for critical event: ${event.rule}`);

    } catch (error) {
      console.error(`❌ Failed to send notification: ${error}`);
    }
  }

  // Generate cryptographically secure and meaningful security event ID
  private generateSecurityEventId(event: FalcoEvent): string {
    // Use UUID v4 for cryptographic security
    const uuid = randomUUID();
    
    // Create a more meaningful ID with timestamp and rule hash
    const ruleHash = this.hashString(event.rule).substring(0, 8);
    
    // Format: falco-YYYYMMDD-HHMMSS-{rule_hash}-{uuid_short}
    const date = new Date();
    const dateStr = date.toISOString().replace(/[-:]/g, '').split('T')[0]; // YYYYMMDD
    const timeStr = date.toISOString().split('T')[1].replace(/[-:.]/g, '').substring(0, 6); // HHMMSS
    const uuidShort = uuid.split('-')[0]; // First part of UUID
    
    return `falco-${dateStr}-${timeStr}-${ruleHash}-${uuidShort}`;
  }

  // Simple string hash for rule identification (not cryptographic, just for readability)
  private hashString(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
  }

  // Map Falco priority to security event severity
  private mapPriorityToSeverity(priority: string): 'low' | 'medium' | 'high' | 'critical' {
    switch (priority?.toUpperCase()) {
      case 'CRITICAL':
        return 'critical';
      case 'ERROR':
        return 'high';
      case 'WARNING':
        return 'medium';
      case 'NOTICE':
      case 'INFO':
        return 'low';
      default:
        return 'medium';
    }
  }

  // Test notification channels
  async testNotifications(channels?: string[]): Promise<any> {
    if (!this.notificationManager) {
      throw new Error('Notification manager not initialized');
    }

    const testEvent: SecurityEvent = {
      id: 'test-' + Date.now(),
      timestamp: new Date().toISOString(),
      severity: 'low',
      rule: 'Test Notification',
      description: 'This is a test notification from Falco MCP Server',
      source: 'falco-test',
      tags: ['test'],
      metadata: { test: true }
    };

    try {
      if (channels) {
        await this.notificationManager.sendAlert(testEvent, channels);
      } else {
        await this.notificationManager.sendAlert(testEvent);
      }

      return {
        success: true,
        message: 'Test notification sent successfully',
        channels: channels || ['default']
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  // Get notification status
  getNotificationStatus(): any {
    if (!this.notificationManager) {
      return {
        enabled: false,
        message: 'Notification manager not initialized'
      };
    }

    return {
      enabled: true,
      channels: this.notificationManager.getChannelStatus(),
      message: 'Notification manager active'
    };
  }
}