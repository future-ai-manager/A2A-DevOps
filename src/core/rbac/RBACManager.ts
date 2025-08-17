import { EventEmitter } from 'events';
import { RBACOrchestrator, QueryContext, AggregatedPermissions } from './RBACOrchestrator';
import { K8sRBACAgent } from './subagents/K8sRBACAgent';
import { AWSIAMAgent } from './subagents/AWSIAMAgent';

/**
 * RBAC 시스템의 메인 매니저
 * 기존 KubernetesClient와 ConnectionManager를 통합하여 권한 기반 접근 제어 제공
 */
export class RBACManager extends EventEmitter {
  private orchestrator: RBACOrchestrator;
  private initialized: boolean = false;

  constructor() {
    super();
    this.orchestrator = new RBACOrchestrator();
    this.setupEventHandlers();
  }

  /**
   * RBAC 시스템 초기화
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      // Kubernetes RBAC Agent 등록 (Kubernetes 환경에서 활성화)
      try {
        const k8sAgent = new K8sRBACAgent();
        if (await k8sAgent.validateConnection()) {
          this.orchestrator.registerSubAgent(k8sAgent);
          this.emit('agentRegistered', { agent: 'kubernetes', status: 'success' });
        } else {
          this.emit('agentSkipped', { agent: 'kubernetes', reason: 'connection_failed' });
        }
      } catch (k8sError) {
        // Kubernetes 환경이 아니거나 설정되지 않음 - 정상적인 상황
        this.emit('agentSkipped', { agent: 'kubernetes', reason: 'not_available', details: k8sError.message });
      }

      // AWS IAM Agent 등록 (AWS 환경에서만 활성화)
      try {
        const awsAgent = new AWSIAMAgent();
        if (await awsAgent.validateConnection()) {
          this.orchestrator.registerSubAgent(awsAgent);
          this.emit('agentRegistered', { agent: 'aws', status: 'success' });
        } else {
          this.emit('agentSkipped', { agent: 'aws', reason: 'connection_failed' });
        }
      } catch (awsError) {
        // AWS 환경이 아니거나 설정되지 않음 - 정상적인 상황
        this.emit('agentSkipped', { agent: 'aws', reason: 'not_available', details: awsError.message });
      }

      // 향후 GCP, Azure Agent도 여기서 등록

      // 등록된 에이전트 확인
      const registeredAgents = this.orchestrator.getRegisteredAgents();
      
      this.initialized = true;
      this.emit('initialized', {
        registeredAgents,
        timestamp: new Date(),
        mode: registeredAgents.length > 0 ? 'full' : 'demo'
      });
      
      if (registeredAgents.length === 0) {
        console.warn('⚠️ No RBAC agents available - running in demo mode with basic permissions');
      }
    } catch (error) {
      this.emit('error', `RBAC Manager initialization failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * 사용자 쿼리에 대한 권한 확인
   */
  async checkQueryPermissions(
    user: string,
    query: string,
    options: {
      resource?: string;
      namespace?: string;
      verb?: string;
      cluster?: string;
      sessionId?: string;
    } = {}
  ): Promise<AggregatedPermissions> {
    if (!this.initialized) {
      await this.initialize();
    }

    const context: QueryContext = {
      user,
      resource: options.resource || this.extractResourceFromQuery(query),
      namespace: options.namespace,
      verb: options.verb || this.extractVerbFromQuery(query),
      cluster: options.cluster || await this.getCurrentCluster(),
      sessionId: options.sessionId
    };

    return await this.orchestrator.resolvePermissions(context);
  }

  /**
   * 특정 리소스에 대한 권한 확인
   */
  async checkResourcePermission(
    user: string,
    resource: string,
    verb: string = 'get',
    namespace?: string
  ): Promise<AggregatedPermissions> {
    if (!this.initialized) {
      await this.initialize();
    }

    const context: QueryContext = {
      user,
      resource,
      verb,
      namespace,
      cluster: await this.getCurrentCluster()
    };

    return await this.orchestrator.resolvePermissions(context);
  }

  /**
   * 사용자가 접근 가능한 네임스페이스 목록
   */
  async getAccessibleNamespaces(user: string): Promise<string[]> {
    const permissions = await this.checkResourcePermission(user, 'pods', 'list');
    return permissions.effectiveNamespaces;
  }

  /**
   * 사용자의 전체 권한 요약
   */
  async getUserPermissionSummary(user: string): Promise<UserPermissionSummary> {
    if (!this.initialized) {
      await this.initialize();
    }

    const commonResources = ['pods', 'services', 'deployments', 'secrets', 'configmaps'];
    const permissionChecks = await Promise.all(
      commonResources.map(async resource => ({
        resource,
        permissions: await this.checkResourcePermission(user, resource, 'get')
      }))
    );

    const allowedResources = permissionChecks
      .filter(check => check.permissions.overallAllowed)
      .map(check => check.resource);

    const accessibleNamespaces = await this.getAccessibleNamespaces(user);

    // 플랫폼별 상태 확인
    const connectionStatus = await this.orchestrator.validateAllConnections();

    return {
      user,
      allowedResources,
      accessibleNamespaces,
      platformStatus: Object.fromEntries(connectionStatus),
      registeredAgents: this.orchestrator.getRegisteredAgents(),
      lastChecked: new Date(),
      riskLevel: this.calculateUserRiskLevel(permissionChecks)
    };
  }

  /**
   * 동적 Agent 등록 (런타임에 새 플랫폼 추가)
   */
  async registerNewAgent(agentType: 'gcp' | 'azure' | 'custom', agent: any): Promise<boolean> {
    try {
      if (await agent.validateConnection()) {
        this.orchestrator.registerSubAgent(agent);
        
        this.emit('agentRegistered', {
          type: agentType,
          platform: agent.platform,
          timestamp: new Date()
        });
        
        return true;
      }
      return false;
    } catch (error) {
      this.emit('error', `Failed to register ${agentType} agent: ${error.message}`);
      return false;
    }
  }

  /**
   * 권한 캐시 관리
   */
  async refreshUserPermissions(user: string): Promise<void> {
    this.orchestrator.invalidatePermissionCache(user);
    
    this.emit('permissionsRefreshed', {
      user,
      timestamp: new Date()
    });
  }

  /**
   * 모든 권한 캐시 무효화
   */
  invalidateAllPermissions(): void {
    this.orchestrator.invalidatePermissionCache();
    
    this.emit('allPermissionsInvalidated', {
      timestamp: new Date()
    });
  }

  /**
   * 시스템 상태 확인
   */
  async getSystemStatus(): Promise<RBACSystemStatus> {
    const connectionStatus = await this.orchestrator.validateAllConnections();
    
    return {
      initialized: this.initialized,
      registeredAgents: this.orchestrator.getRegisteredAgents(),
      platformConnections: Object.fromEntries(connectionStatus),
      lastStatusCheck: new Date()
    };
  }

  /**
   * 쿼리에서 리소스 추출 (간단한 파싱)
   */
  private extractResourceFromQuery(query: string): string {
    const lowerQuery = query.toLowerCase();
    
    // 일반적인 리소스들 확인
    const resourceKeywords = [
      'pods', 'pod', 'services', 'service', 'deployments', 'deployment',
      'secrets', 'secret', 'configmaps', 'configmap', 'nodes', 'node',
      'namespaces', 'namespace', 'ingresses', 'ingress'
    ];

    for (const keyword of resourceKeywords) {
      if (lowerQuery.includes(keyword)) {
        // 복수형으로 정규화
        if (keyword.endsWith('s')) {
          return keyword;
        } else {
          return keyword + 's';
        }
      }
    }

    return 'pods'; // 기본값
  }

  /**
   * 쿼리에서 동사 추출
   */
  private extractVerbFromQuery(query: string): string {
    const lowerQuery = query.toLowerCase();
    
    // 동작을 나타내는 키워드들
    if (lowerQuery.includes('create') || lowerQuery.includes('add')) {
      return 'create';
    } else if (lowerQuery.includes('delete') || lowerQuery.includes('remove')) {
      return 'delete';
    } else if (lowerQuery.includes('update') || lowerQuery.includes('modify') || lowerQuery.includes('edit')) {
      return 'update';
    } else if (lowerQuery.includes('list') || lowerQuery.includes('show all')) {
      return 'list';
    } else {
      return 'get'; // 기본값
    }
  }

  /**
   * 현재 클러스터 컨텍스트 확인
   */
  private async getCurrentCluster(): Promise<string> {
    try {
      const { execAsync } = await import('child_process');
      const { promisify } = await import('util');
      const exec = promisify(execAsync);
      
      const { stdout } = await exec('kubectl config current-context');
      return stdout.trim();
    } catch {
      return 'unknown';
    }
  }

  /**
   * 사용자 위험도 계산
   */
  private calculateUserRiskLevel(permissionChecks: any[]): 'low' | 'medium' | 'high' {
    const highRiskResources = ['secrets', 'clusterroles', 'nodes'];
    const hasHighRiskAccess = permissionChecks.some(check => 
      highRiskResources.includes(check.resource) && check.permissions.overallAllowed
    );

    if (hasHighRiskAccess) {
      return 'high';
    }

    const allowedResourceCount = permissionChecks.filter(check => check.permissions.overallAllowed).length;
    
    if (allowedResourceCount > 3) {
      return 'medium';
    }

    return 'low';
  }

  /**
   * 이벤트 핸들러 설정
   */
  private setupEventHandlers(): void {
    this.orchestrator.on('permissionsResolved', (data) => {
      this.emit('permissionsResolved', data);
    });

    this.orchestrator.on('permissionChanged', (data) => {
      this.emit('permissionChanged', data);
    });

    this.orchestrator.on('agentError', (data) => {
      this.emit('agentError', data);
    });
  }

  /**
   * 정리 및 종료
   */
  async cleanup(): Promise<void> {
    this.orchestrator.removeAllListeners();
    this.removeAllListeners();
    this.initialized = false;
  }
}

// 타입 정의들
interface UserPermissionSummary {
  user: string;
  allowedResources: string[];
  accessibleNamespaces: string[];
  platformStatus: { [platform: string]: boolean };
  registeredAgents: string[];
  lastChecked: Date;
  riskLevel: 'low' | 'medium' | 'high';
}

interface RBACSystemStatus {
  initialized: boolean;
  registeredAgents: string[];
  platformConnections: { [platform: string]: boolean };
  lastStatusCheck: Date;
}

// 기본 인스턴스 export (싱글톤 패턴)
export const rbacManager = new RBACManager();