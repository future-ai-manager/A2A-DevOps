import { EventEmitter } from 'events';

export interface PermissionResult {
  platform: string;
  allowed: boolean;
  roles: string[];
  restrictions?: {
    namespaces?: string[];
    resources?: string[];
    verbs?: string[];
  };
  details?: any;
  error?: string;
  suggestions?: string[];
}

export interface QueryContext {
  user: string;
  resource: string;
  namespace?: string;
  verb?: string;
  cluster?: string;
  sessionId?: string;
}

export interface AggregatedPermissions {
  overallAllowed: boolean;
  platformResults: PermissionResult[];
  resolvedPermissions: string[];
  conflicts: PermissionConflict[];
  recommendations: string[];
  effectiveNamespaces: string[];
  riskLevel: 'low' | 'medium' | 'high';
}

export interface PermissionConflict {
  type: 'platform-mismatch' | 'namespace-restriction' | 'verb-limitation';
  description: string;
  resolution: string;
  affectedPlatforms: string[];
}

export abstract class RBACSubAgent extends EventEmitter {
  abstract platform: string;
  
  abstract checkPermissions(context: QueryContext): Promise<PermissionResult>;
  abstract validateConnection(): Promise<boolean>;
  abstract getUserRoles(user: string): Promise<string[]>;
  
  // 선택적 구현 메서드들
  async cachePermissions(permissions: PermissionResult): Promise<void> {
    // 기본 구현 - 각 subagent에서 재정의 가능
  }
  
  async refreshPermissions(user: string): Promise<void> {
    // 기본 구현 - 권한 캐시 갱신
  }
}

/**
 * RBAC 오케스트레이터 - 다중 플랫폼 권한 관리 중앙 조정자
 */
export class RBACOrchestrator extends EventEmitter {
  private subAgents: Map<string, RBACSubAgent> = new Map();
  private permissionCache: Map<string, { result: PermissionResult; timestamp: number }> = new Map();
  private readonly CACHE_TTL = 300000; // 5분

  constructor() {
    super();
    this.setMaxListeners(50);
  }

  /**
   * RBAC SubAgent 등록
   */
  registerSubAgent(agent: RBACSubAgent): void {
    this.subAgents.set(agent.platform, agent);
    
    // Agent 이벤트 리스닝
    agent.on('permissionChanged', (data) => {
      this.emit('permissionChanged', { platform: agent.platform, ...data });
    });
    
    agent.on('error', (error) => {
      this.emit('agentError', { platform: agent.platform, error });
    });
  }

  /**
   * 다중 플랫폼 권한 해석 및 병합
   */
  async resolvePermissions(context: QueryContext): Promise<AggregatedPermissions> {
    // 1. 관련된 subagent들 결정
    const relevantAgents = await this.determineRelevantAgents(context);
    
    // 2. 각 플랫폼에서 병렬로 권한 확인
    const permissionResults = await Promise.allSettled(
      relevantAgents.map(agent => this.checkAgentPermissions(agent, context))
    );

    // 3. 결과 처리 및 실패한 agent 처리
    const processedResults = permissionResults.map((result, index) => {
      if (result.status === 'fulfilled') {
        return result.value;
      } else {
        return {
          platform: relevantAgents[index].platform,
          allowed: false,
          roles: [],
          error: result.reason.message,
          suggestions: [`Check ${relevantAgents[index].platform} connectivity and authentication`]
        };
      }
    });

    // 4. 권한 병합 및 충돌 해결
    return await this.aggregatePermissions(processedResults, context);
  }

  /**
   * 관련된 subagent들 결정
   */
  private async determineRelevantAgents(context: QueryContext): Promise<RBACSubAgent[]> {
    const relevantAgents: RBACSubAgent[] = [];

    // Kubernetes는 항상 필요
    const k8sAgent = this.subAgents.get('kubernetes');
    if (k8sAgent && await k8sAgent.validateConnection()) {
      relevantAgents.push(k8sAgent);
    }

    // 클러스터 컨텍스트에 따라 클라우드 agent 결정
    if (context.cluster) {
      if (context.cluster.includes('eks') || context.cluster.includes('aws')) {
        const awsAgent = this.subAgents.get('aws');
        if (awsAgent && await awsAgent.validateConnection()) {
          relevantAgents.push(awsAgent);
        }
      }

      if (context.cluster.includes('gke') || context.cluster.includes('gcp')) {
        const gcpAgent = this.subAgents.get('gcp');
        if (gcpAgent && await gcpAgent.validateConnection()) {
          relevantAgents.push(gcpAgent);
        }
      }

      if (context.cluster.includes('aks') || context.cluster.includes('azure')) {
        const azureAgent = this.subAgents.get('azure');
        if (azureAgent && await azureAgent.validateConnection()) {
          relevantAgents.push(azureAgent);
        }
      }
    }

    return relevantAgents;
  }

  /**
   * Agent별 권한 확인 (캐싱 포함)
   */
  private async checkAgentPermissions(agent: RBACSubAgent, context: QueryContext): Promise<PermissionResult> {
    const cacheKey = `${agent.platform}:${context.user}:${context.resource}:${context.namespace || 'default'}`;
    
    // 캐시 확인
    const cached = this.permissionCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < this.CACHE_TTL) {
      return cached.result;
    }

    // 실제 권한 확인
    const result = await agent.checkPermissions(context);
    
    // 캐시 저장
    this.permissionCache.set(cacheKey, {
      result,
      timestamp: Date.now()
    });

    return result;
  }

  /**
   * 권한 결과 병합 및 최종 결정
   */
  private async aggregatePermissions(
    results: PermissionResult[], 
    context: QueryContext
  ): Promise<AggregatedPermissions> {
    const aggregated: AggregatedPermissions = {
      overallAllowed: false,
      platformResults: results,
      resolvedPermissions: [],
      conflicts: [],
      recommendations: [],
      effectiveNamespaces: [],
      riskLevel: 'low'
    };

    // Kubernetes 결과 우선 확인
    const k8sResult = results.find(r => r.platform === 'kubernetes');
    const cloudResults = results.filter(r => r.platform !== 'kubernetes');

    // 기본 정책: Kubernetes에서 허용되면 진행
    if (k8sResult?.allowed) {
      aggregated.overallAllowed = true;
      aggregated.resolvedPermissions = this.extractPermissions(k8sResult);
      aggregated.effectiveNamespaces = k8sResult.restrictions?.namespaces || ['default'];
    }

    // 클라우드 플랫폼 권한 충돌 감지
    const deniedCloudPlatforms = cloudResults.filter(r => !r.allowed);
    if (deniedCloudPlatforms.length > 0 && k8sResult?.allowed) {
      aggregated.conflicts.push({
        type: 'platform-mismatch',
        description: `Kubernetes allows but ${deniedCloudPlatforms.map(p => p.platform).join(', ')} restricts`,
        resolution: 'Proceeding with Kubernetes permissions, verify cloud provider access',
        affectedPlatforms: deniedCloudPlatforms.map(p => p.platform)
      });
      aggregated.riskLevel = 'medium';
    }

    // 모든 플랫폼에서 거부된 경우
    if (!k8sResult?.allowed || results.every(r => !r.allowed)) {
      aggregated.overallAllowed = false;
      aggregated.recommendations = this.generateRecommendations(results, context);
      aggregated.riskLevel = 'high';
    }

    // 네임스페이스 제한 병합
    aggregated.effectiveNamespaces = this.mergeNamespaceRestrictions(results);

    this.emit('permissionsResolved', {
      context,
      result: aggregated,
      timestamp: new Date()
    });

    return aggregated;
  }

  /**
   * 권한 결과에서 구체적인 권한 추출
   */
  private extractPermissions(result: PermissionResult): string[] {
    const permissions: string[] = [];
    
    if (result.details && typeof result.details === 'object') {
      Object.entries(result.details).forEach(([action, allowed]) => {
        if (allowed) {
          permissions.push(action);
        }
      });
    }
    
    return permissions;
  }

  /**
   * 네임스페이스 제한 병합
   */
  private mergeNamespaceRestrictions(results: PermissionResult[]): string[] {
    const allNamespaces = results
      .filter(r => r.allowed && r.restrictions?.namespaces)
      .flatMap(r => r.restrictions!.namespaces!);

    // 교집합 계산 (모든 플랫폼에서 공통으로 허용된 네임스페이스)
    if (allNamespaces.length === 0) {
      return ['default'];
    }

    const namespaceGroups = results
      .filter(r => r.allowed && r.restrictions?.namespaces)
      .map(r => r.restrictions!.namespaces!);

    if (namespaceGroups.length === 0) {
      return allNamespaces;
    }

    return namespaceGroups.reduce((intersection, current) =>
      intersection.filter(ns => current.includes(ns))
    );
  }

  /**
   * 권한 부족시 추천사항 생성
   */
  private generateRecommendations(results: PermissionResult[], context: QueryContext): string[] {
    const recommendations: string[] = [];
    
    const deniedResults = results.filter(r => !r.allowed);
    
    for (const denied of deniedResults) {
      if (denied.suggestions) {
        recommendations.push(...denied.suggestions);
      } else {
        switch (denied.platform) {
          case 'kubernetes':
            recommendations.push('Request Kubernetes RBAC permissions for the required resources');
            recommendations.push(`Check permissions with: kubectl auth can-i ${context.verb || 'get'} ${context.resource}`);
            break;
          case 'aws':
            recommendations.push('Verify AWS IAM permissions for EKS access');
            recommendations.push('Check AWS authentication: aws sts get-caller-identity');
            break;
          case 'gcp':
            recommendations.push('Verify GCP IAM roles for GKE access');
            recommendations.push('Check GCP authentication: gcloud auth list');
            break;
          case 'azure':
            recommendations.push('Verify Azure RBAC permissions for AKS access');
            recommendations.push('Check Azure authentication: az account show');
            break;
        }
      }
    }

    // 일반적인 추천사항
    if (recommendations.length === 0) {
      recommendations.push('Contact your cluster administrator for access');
      recommendations.push('Use a2a auth status to check authentication status');
    }

    return [...new Set(recommendations)]; // 중복 제거
  }

  /**
   * 권한 캐시 무효화
   */
  invalidatePermissionCache(user?: string, platform?: string): void {
    if (!user && !platform) {
      this.permissionCache.clear();
      return;
    }

    const keysToDelete: string[] = [];
    for (const key of this.permissionCache.keys()) {
      const [keyPlatform, keyUser] = key.split(':');
      
      if ((platform && keyPlatform === platform) || (user && keyUser === user)) {
        keysToDelete.push(key);
      }
    }

    keysToDelete.forEach(key => this.permissionCache.delete(key));
  }

  /**
   * 등록된 모든 subagent의 연결 상태 확인
   */
  async validateAllConnections(): Promise<Map<string, boolean>> {
    const connectionStatus = new Map<string, boolean>();
    
    for (const [platform, agent] of this.subAgents) {
      try {
        const isConnected = await agent.validateConnection();
        connectionStatus.set(platform, isConnected);
      } catch (error) {
        connectionStatus.set(platform, false);
      }
    }

    return connectionStatus;
  }

  /**
   * 현재 등록된 subagent 목록
   */
  getRegisteredAgents(): string[] {
    return Array.from(this.subAgents.keys());
  }
}