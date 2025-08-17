import { exec } from 'child_process';
import { promisify } from 'util';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';
import { RBACSubAgent, PermissionResult, QueryContext } from '../RBACOrchestrator';

const execAsync = promisify(exec);

interface K8sRole {
  name: string;
  type: 'Role' | 'ClusterRole';
  namespace?: string;
  permissions: K8sPermission[];
}

interface K8sPermission {
  verbs: string[];
  resources: string[];
  resourceNames?: string[];
  namespaces?: string[];
}

interface K8sUserInfo {
  name: string;
  groups: string[];
  uid?: string;
}

/**
 * Kubernetes RBAC 전담 SubAgent
 * 현재 KubernetesClient.ts의 권한 확인 기능을 확장하여 구현
 */
export class K8sRBACAgent extends RBACSubAgent {
  public readonly platform = 'kubernetes';
  private currentContext: string | null = null;
  private userInfo: K8sUserInfo | null = null;

  constructor() {
    super();
  }

  /**
   * Kubernetes 연결 유효성 확인
   */
  async validateConnection(): Promise<boolean> {
    try {
      await execAsync('kubectl cluster-info --request-timeout=5s');
      return true;
    } catch (error) {
      this.emit('error', `Kubernetes connection failed: ${error}`);
      return false;
    }
  }

  /**
   * 사용자의 Kubernetes 권한 확인
   */
  async checkPermissions(context: QueryContext): Promise<PermissionResult> {
    try {
      // 1. 현재 컨텍스트 확인
      await this.updateCurrentContext();
      
      // 2. 사용자 정보 확인
      await this.updateUserInfo();

      // 3. 구체적인 리소스별 권한 확인
      const resourcePermissions = await this.checkResourcePermissions(context);

      // 4. 네임스페이스 제한 확인
      const namespaceRestrictions = await this.getNamespaceRestrictions(context);

      // 5. 사용자 역할 확인
      const userRoles = await this.getUserRoles(context.user);

      const allowed = this.determineOverallPermission(resourcePermissions, context);

      return {
        platform: this.platform,
        allowed,
        roles: userRoles,
        restrictions: {
          namespaces: namespaceRestrictions,
          resources: this.getResourceRestrictions(resourcePermissions),
          verbs: this.getVerbRestrictions(resourcePermissions)
        },
        details: {
          context: this.currentContext,
          user: this.userInfo,
          resourcePermissions,
          checkedAt: new Date().toISOString()
        }
      };
    } catch (error) {
      return {
        platform: this.platform,
        allowed: false,
        roles: [],
        error: error.message,
        suggestions: [
          'Check kubectl configuration: kubectl config view',
          'Verify cluster connectivity: kubectl cluster-info',
          'Check current context: kubectl config current-context'
        ]
      };
    }
  }

  /**
   * 현재 컨텍스트 정보 업데이트
   */
  private async updateCurrentContext(): Promise<void> {
    try {
      const { stdout } = await execAsync('kubectl config current-context');
      this.currentContext = stdout.trim();
    } catch (error) {
      throw new Error('No current Kubernetes context found');
    }
  }

  /**
   * 현재 사용자 정보 확인
   */
  private async updateUserInfo(): Promise<void> {
    try {
      // kubectl auth whoami 사용 (kubectl 1.28+)
      try {
        const { stdout } = await execAsync('kubectl auth whoami -o json');
        const whoamiResult = JSON.parse(stdout);
        this.userInfo = {
          name: whoamiResult.spec?.user || 'unknown',
          groups: whoamiResult.spec?.groups || [],
          uid: whoamiResult.spec?.uid
        };
      } catch {
        // whoami가 지원되지 않는 경우 kubeconfig에서 추출
        const { stdout } = await execAsync('kubectl config view --minify --raw -o json');
        const config = JSON.parse(stdout);
        
        this.userInfo = {
          name: config.users?.[0]?.name || 'current-user',
          groups: [], // kubeconfig에서는 그룹 정보를 직접 얻기 어려움
        };
      }
    } catch (error) {
      this.userInfo = {
        name: 'unknown',
        groups: []
      };
    }
  }

  /**
   * 구체적인 리소스별 권한 확인
   */
  private async checkResourcePermissions(context: QueryContext): Promise<Map<string, boolean>> {
    const permissions = new Map<string, boolean>();
    
    // 기본 동사들
    const verbs = ['get', 'list', 'create', 'update', 'patch', 'delete', 'watch'];
    
    // 컨텍스트에서 요청된 리소스와 동사
    const targetResource = context.resource || 'pods';
    const targetVerb = context.verb || 'get';
    const targetNamespace = context.namespace;

    // 요청된 동작 우선 확인
    const primaryAction = `${targetVerb} ${targetResource}`;
    permissions.set(primaryAction, await this.canI(targetVerb, targetResource, targetNamespace));

    // 관련된 다른 동작들도 확인
    for (const verb of verbs) {
      if (verb !== targetVerb) {
        const action = `${verb} ${targetResource}`;
        permissions.set(action, await this.canI(verb, targetResource, targetNamespace));
      }
    }

    // 관련 리소스들도 확인 (예: pods와 관련된 logs, events 등)
    const relatedResources = this.getRelatedResources(targetResource);
    for (const relatedResource of relatedResources) {
      const action = `get ${relatedResource}`;
      permissions.set(action, await this.canI('get', relatedResource, targetNamespace));
    }

    return permissions;
  }

  /**
   * kubectl auth can-i 실행
   */
  private async canI(verb: string, resource: string, namespace?: string): Promise<boolean> {
    try {
      const namespaceFlag = namespace ? `-n ${namespace}` : '';
      await execAsync(`kubectl auth can-i ${verb} ${resource} ${namespaceFlag}`);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * 리소스별 관련 리소스 목록
   */
  private getRelatedResources(resource: string): string[] {
    const relatedMap: { [key: string]: string[] } = {
      'pods': ['pods/log', 'pods/status', 'events', 'replicasets'],
      'deployments': ['replicasets', 'pods', 'events'],
      'services': ['endpoints', 'ingresses'],
      'secrets': ['configmaps'],
      'nodes': ['pods', 'events'],
      'namespaces': ['pods', 'services', 'secrets']
    };

    return relatedMap[resource] || [];
  }

  /**
   * 사용자가 접근 가능한 네임스페이스 확인
   */
  private async getNamespaceRestrictions(context: QueryContext): Promise<string[]> {
    try {
      // 모든 네임스페이스 목록 가져오기
      const { stdout } = await execAsync('kubectl get namespaces -o name --no-headers');
      const allNamespaces = stdout
        .split('\n')
        .map(line => line.replace('namespace/', '').trim())
        .filter(ns => ns.length > 0);

      // 각 네임스페이스에 대한 접근 권한 확인
      const accessibleNamespaces: string[] = [];
      
      for (const namespace of allNamespaces) {
        try {
          // 각 네임스페이스에서 기본적인 권한 확인
          await execAsync(`kubectl auth can-i get pods -n ${namespace}`);
          accessibleNamespaces.push(namespace);
        } catch {
          // 이 네임스페이스는 접근 불가
        }
      }

      // 접근 가능한 네임스페이스가 없으면 default만 반환
      return accessibleNamespaces.length > 0 ? accessibleNamespaces : ['default'];
    } catch (error) {
      // 네임스페이스 목록을 가져올 수 없으면 default만 반환
      return ['default'];
    }
  }

  /**
   * 사용자의 Kubernetes 역할 확인
   */
  async getUserRoles(user: string): Promise<string[]> {
    try {
      const roles: string[] = [];

      // RoleBinding 확인
      try {
        const { stdout: roleBindings } = await execAsync('kubectl get rolebindings -A -o json');
        const rbData = JSON.parse(roleBindings);
        
        for (const binding of rbData.items) {
          if (this.isUserInBinding(binding, user)) {
            roles.push(`${binding.metadata.namespace}:${binding.roleRef.name}`);
          }
        }
      } catch {
        // RoleBinding 조회 실패
      }

      // ClusterRoleBinding 확인
      try {
        const { stdout: clusterRoleBindings } = await execAsync('kubectl get clusterrolebindings -o json');
        const crbData = JSON.parse(clusterRoleBindings);
        
        for (const binding of crbData.items) {
          if (this.isUserInBinding(binding, user)) {
            roles.push(`cluster:${binding.roleRef.name}`);
          }
        }
      } catch {
        // ClusterRoleBinding 조회 실패
      }

      return roles.length > 0 ? roles : ['unknown'];
    } catch (error) {
      return ['error-fetching-roles'];
    }
  }

  /**
   * 바인딩에서 사용자 확인
   */
  private isUserInBinding(binding: any, user: string): boolean {
    if (!binding.subjects) return false;

    for (const subject of binding.subjects) {
      // 직접 사용자 매칭
      if (subject.kind === 'User' && subject.name === user) {
        return true;
      }
      
      // 서비스 계정 매칭
      if (subject.kind === 'ServiceAccount' && this.userInfo?.name.includes(subject.name)) {
        return true;
      }
      
      // 그룹 매칭
      if (subject.kind === 'Group' && this.userInfo?.groups.includes(subject.name)) {
        return true;
      }
    }

    return false;
  }

  /**
   * 전체 권한 허용 여부 결정
   */
  private determineOverallPermission(permissions: Map<string, boolean>, context: QueryContext): boolean {
    const targetAction = `${context.verb || 'get'} ${context.resource || 'pods'}`;
    
    // 요청된 구체적인 동작이 허용되면 OK
    if (permissions.get(targetAction)) {
      return true;
    }

    // 최소한 get 권한이라도 있으면 읽기 전용으로 허용
    const readAction = `get ${context.resource || 'pods'}`;
    return permissions.get(readAction) || false;
  }

  /**
   * 리소스 제한 사항 추출
   */
  private getResourceRestrictions(permissions: Map<string, boolean>): string[] {
    const allowedResources: string[] = [];
    
    for (const [action, allowed] of permissions) {
      if (allowed) {
        const resource = action.split(' ')[1];
        if (resource && !allowedResources.includes(resource)) {
          allowedResources.push(resource);
        }
      }
    }

    return allowedResources;
  }

  /**
   * 동사 제한 사항 추출
   */
  private getVerbRestrictions(permissions: Map<string, boolean>): string[] {
    const allowedVerbs: string[] = [];
    
    for (const [action, allowed] of permissions) {
      if (allowed) {
        const verb = action.split(' ')[0];
        if (verb && !allowedVerbs.includes(verb)) {
          allowedVerbs.push(verb);
        }
      }
    }

    return allowedVerbs;
  }

  /**
   * 권한 캐싱 (오버라이드)
   */
  async cachePermissions(permissions: PermissionResult): Promise<void> {
    // K8s 특화된 캐싱 로직
    this.emit('permissionsCached', {
      platform: this.platform,
      context: this.currentContext,
      user: this.userInfo?.name,
      timestamp: new Date()
    });
  }

  /**
   * 권한 새로고침 (오버라이드)
   */
  async refreshPermissions(user: string): Promise<void> {
    try {
      // 사용자 정보 갱신
      await this.updateUserInfo();
      
      // 권한 캐시 무효화 이벤트 발생
      this.emit('permissionChanged', {
        platform: this.platform,
        user,
        action: 'refreshed',
        timestamp: new Date()
      });
    } catch (error) {
      this.emit('error', `Failed to refresh permissions: ${error.message}`);
    }
  }

  /**
   * Kubernetes 클러스터 정보 가져오기
   */
  async getClusterInfo(): Promise<any> {
    try {
      const { stdout } = await execAsync('kubectl cluster-info --output=json');
      return JSON.parse(stdout);
    } catch (error) {
      return null;
    }
  }

  /**
   * 현재 컨텍스트와 사용자 정보 반환
   */
  getCurrentContextInfo(): { context: string | null; user: K8sUserInfo | null } {
    return {
      context: this.currentContext,
      user: this.userInfo
    };
  }
}