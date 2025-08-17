# RBAC SubAgent 구현 전략

## 현실적인 구현 접근법

### 1. 플랫폼별 RBAC SubAgent 아키텍처

```
a2a-platform/
├── src/core/rbac/
│   ├── RBACOrchestrator.ts          # 메인 RBAC 조정자
│   ├── subagents/
│   │   ├── K8sRBACAgent.ts          # Kubernetes RBAC 전담
│   │   ├── AWSIAMAgent.ts           # AWS IAM 전담  
│   │   ├── GCPIAMAgent.ts           # GCP IAM 전담
│   │   ├── AzureRBACAgent.ts        # Azure RBAC 전담
│   │   └── LocalRBACAgent.ts        # 로컬 클러스터 RBAC
│   ├── aggregators/
│   │   ├── PermissionAggregator.ts  # 다중 플랫폼 권한 병합
│   │   └── PolicyResolver.ts        # 충돌 권한 해결
│   └── cache/
│       ├── PermissionCache.ts       # 권한 정보 캐싱
│       └── RBACEventStore.ts        # 권한 변경 이벤트 추적
```

### 2. 현재 구현 가능한 기본 구조

```typescript
// 현재 코드베이스 활용 가능
interface RBACSubAgent {
  platform: 'kubernetes' | 'aws' | 'gcp' | 'azure' | 'local';
  
  // 현재 KubernetesClient.ts의 checkPermissions() 확장
  checkPermissions(user: string, resource: string): Promise<PermissionResult>;
  
  // 현재 ConnectionManager.ts 기반으로 구현 가능
  validateConnection(): Promise<boolean>;
  
  // 새로 구현 필요
  resolveUserRoles(user: string): Promise<Role[]>;
  cachePermissions(permissions: Permission[]): Promise<void>;
}

class RBACOrchestrator {
  private subAgents: Map<string, RBACSubAgent> = new Map();
  
  constructor() {
    // 현재 존재하는 KubernetesClient를 기반으로 K8s subagent 생성
    this.subAgents.set('kubernetes', new K8sRBACAgent());
    
    // AWS/GCP/Azure는 단계적으로 추가
    this.subAgents.set('aws', new AWSIAMAgent());
  }

  async resolvePermissions(context: QueryContext): Promise<AggregatedPermissions> {
    const relevantAgents = this.determineRelevantAgents(context);
    
    // 병렬로 각 플랫폼 권한 확인
    const permissionResults = await Promise.all(
      relevantAgents.map(agent => agent.checkPermissions(context.user, context.resource))
    );
    
    // 권한 결과 병합 및 충돌 해결
    return this.aggregatePermissions(permissionResults);
  }
}
```

## 구체적인 SubAgent 구현

### 1. Kubernetes RBAC Agent (현재 구현 가능)

```typescript
// 현재 KubernetesClient.ts 기반으로 즉시 구현 가능
class K8sRBACAgent implements RBACSubAgent {
  private kubernetesClient: KubernetesClient; // 현재 존재

  constructor() {
    this.kubernetesClient = new KubernetesClient();
  }

  async checkPermissions(user: string, resource: string): Promise<PermissionResult> {
    // 현재 KubernetesClient.checkPermissions() 활용
    const currentPermissions = await this.kubernetesClient.checkPermissions();
    
    // 구체적인 리소스별 권한 확인
    const specificPermissions = await this.checkSpecificResourcePermissions(resource);
    
    return {
      platform: 'kubernetes',
      allowed: specificPermissions.includes(resource),
      roles: await this.getUserRoles(user),
      namespaceRestrictions: await this.getNamespaceRestrictions(user),
      details: currentPermissions
    };
  }

  private async checkSpecificResourcePermissions(resource: string): Promise<string[]> {
    // 현재 kubectl 기반 구현 가능
    const resourceChecks = [
      `get ${resource}`,
      `list ${resource}`, 
      `create ${resource}`,
      `update ${resource}`,
      `delete ${resource}`
    ];

    const allowedActions: string[] = [];
    
    for (const action of resourceChecks) {
      try {
        await execAsync(`kubectl auth can-i ${action}`);
        allowedActions.push(action);
      } catch {
        // 권한 없음
      }
    }
    
    return allowedActions;
  }

  async getUserRoles(user: string): Promise<Role[]> {
    try {
      // 현재 사용자의 RoleBinding 조회
      const { stdout: roleBindings } = await execAsync(`
        kubectl get rolebindings,clusterrolebindings -A -o json
      `);
      
      const bindings = JSON.parse(roleBindings);
      return this.extractUserRoles(bindings, user);
    } catch (error) {
      return [];
    }
  }

  async getNamespaceRestrictions(user: string): Promise<string[]> {
    // 사용자가 접근 가능한 네임스페이스 확인
    try {
      const { stdout: namespaces } = await execAsync(`kubectl get namespaces -o name`);
      const allNamespaces = namespaces.split('\n').map(ns => ns.replace('namespace/', ''));
      
      const accessibleNamespaces: string[] = [];
      for (const ns of allNamespaces) {
        try {
          await execAsync(`kubectl auth can-i get pods -n ${ns}`);
          accessibleNamespaces.push(ns);
        } catch {
          // 접근 불가
        }
      }
      
      return accessibleNamespaces;
    } catch {
      return ['default']; // fallback
    }
  }
}
```

### 2. AWS IAM Agent (단계적 구현)

```typescript
class AWSIAMAgent implements RBACSubAgent {
  async checkPermissions(user: string, resource: string): Promise<PermissionResult> {
    // 1단계: 기본 AWS 인증 확인 (현재 구현 가능)
    const isAuthenticated = await this.checkAWSAuth();
    if (!isAuthenticated) {
      return { platform: 'aws', allowed: false, error: 'Not authenticated' };
    }

    // 2단계: EKS 권한 확인 (현재 구현 가능)
    const eksPermissions = await this.checkEKSPermissions(resource);
    
    // 3단계: IAM 정책 시뮬레이션 (향후 구현)
    // const simulatedPermissions = await this.simulateIAMPolicy(user, resource);
    
    return {
      platform: 'aws',
      allowed: eksPermissions.allowed,
      roles: eksPermissions.roles,
      details: eksPermissions
    };
  }

  private async checkAWSAuth(): Promise<boolean> {
    try {
      await execAsync('aws sts get-caller-identity');
      return true;
    } catch {
      return false;
    }
  }

  private async checkEKSPermissions(resource: string): Promise<EKSPermissionResult> {
    try {
      // EKS 클러스터 목록 권한 확인
      await execAsync('aws eks list-clusters');
      
      // 구체적인 EKS 권한 확인
      const clusterAccess = await this.checkClusterAccess();
      
      return {
        allowed: clusterAccess.length > 0,
        roles: ['eks-user'], // 실제로는 IAM role 조회
        clusters: clusterAccess
      };
    } catch (error) {
      return {
        allowed: false,
        error: error.message,
        suggestions: [
          'Check AWS credentials: aws configure',
          'Verify EKS permissions in IAM console'
        ]
      };
    }
  }

  private async checkClusterAccess(): Promise<string[]> {
    try {
      const { stdout } = await execAsync('aws eks list-clusters --output json');
      const response = JSON.parse(stdout);
      
      // 각 클러스터별 접근 권한 확인
      const accessibleClusters: string[] = [];
      for (const cluster of response.clusters) {
        try {
          await execAsync(`aws eks describe-cluster --name ${cluster}`);
          accessibleClusters.push(cluster);
        } catch {
          // 이 클러스터는 접근 불가
        }
      }
      
      return accessibleClusters;
    } catch {
      return [];
    }
  }
}
```

### 3. 권한 병합 및 충돌 해결

```typescript
class PermissionAggregator {
  async aggregatePermissions(results: PermissionResult[]): Promise<AggregatedPermissions> {
    const aggregated: AggregatedPermissions = {
      overallAllowed: false,
      platformResults: results,
      resolvedPermissions: [],
      conflicts: [],
      recommendations: []
    };

    // 1. 기본 정책: 모든 플랫폼에서 허용되어야 함
    const allAllowed = results.every(r => r.allowed);
    
    // 2. 예외 정책: Kubernetes에서 허용되면 일단 진행
    const k8sResult = results.find(r => r.platform === 'kubernetes');
    const k8sAllowed = k8sResult?.allowed || false;
    
    // 3. 최종 결정
    aggregated.overallAllowed = allAllowed || k8sAllowed;
    
    // 4. 충돌 감지 및 해결
    if (!allAllowed && k8sAllowed) {
      aggregated.conflicts.push({
        type: 'platform-mismatch',
        description: 'Kubernetes allows but cloud provider restricts',
        resolution: 'Proceeding with Kubernetes permissions only'
      });
    }

    // 5. 권한 향상 추천
    aggregated.recommendations = this.generateRecommendations(results);
    
    return aggregated;
  }

  private generateRecommendations(results: PermissionResult[]): string[] {
    const recommendations: string[] = [];
    
    const deniedPlatforms = results.filter(r => !r.allowed);
    
    for (const denied of deniedPlatforms) {
      switch (denied.platform) {
        case 'aws':
          recommendations.push('Check AWS IAM policies for EKS access');
          break;
        case 'gcp':
          recommendations.push('Verify GCP IAM roles for GKE access');
          break;
        case 'kubernetes':
          recommendations.push('Request additional Kubernetes RBAC permissions');
          break;
      }
    }
    
    return recommendations;
  }
}
```

## 현재 구현 가능성 평가

### ✅ 즉시 구현 가능 (현재 코드베이스 활용)

1. **Kubernetes RBAC Agent**
   - 현재 `KubernetesClient.checkPermissions()` 확장
   - `kubectl auth can-i` 기반 권한 확인
   - 네임스페이스별 권한 제한

2. **기본 AWS IAM Agent**
   - AWS CLI 인증 상태 확인
   - EKS 클러스터 접근 권한 확인
   - 기본적인 권한 검증

3. **권한 캐싱 시스템**
   - 현재 `ConnectionManager` 구조 활용
   - 권한 정보 캐싱으로 성능 개선

### 🔄 단계적 구현 필요

1. **고급 IAM 정책 시뮬레이션**
   ```typescript
   // AWS IAM Policy Simulator API 연동
   async simulateIAMPolicy(user: string, action: string): Promise<SimulationResult> {
     // aws iam simulate-principal-policy 활용
   }
   ```

2. **GCP/Azure IAM Agent**
   - GCP: `gcloud auth` 및 IAM API 연동
   - Azure: `az account` 및 Azure AD API 연동

3. **복합 권한 정책 엔진**
   - 다중 플랫폼 권한 충돌 해결
   - 조건부 권한 평가

### 📋 구현 우선순위

#### Phase 1 (즉시 가능 - 2주)
- [ ] `K8sRBACAgent` 구현 및 현재 `KubernetesClient` 통합
- [ ] 기본 `RBACOrchestrator` 프레임워크
- [ ] 권한 캐싱 시스템

#### Phase 2 (4주 내)
- [ ] `AWSIAMAgent` 기본 구현
- [ ] 권한 병합 로직
- [ ] 네임스페이스 기반 권한 제한

#### Phase 3 (8주 내)
- [ ] GCP/Azure IAM Agent
- [ ] 고급 권한 시뮬레이션
- [ ] 복합 정책 해결

### 실제 사용 예시

```typescript
// 현재 코드베이스에서 즉시 구현 가능한 형태
class QueryProcessor {
  private rbacOrchestrator: RBACOrchestrator;

  async processQuery(query: string, user: string): Promise<QueryResult> {
    // 1. 쿼리 분석하여 필요한 리소스 확인
    const requiredResources = this.analyzeQueryResources(query);
    
    // 2. 사용자 권한 확인
    const permissions = await this.rbacOrchestrator.resolvePermissions({
      user,
      resources: requiredResources,
      cluster: await this.getCurrentCluster()
    });
    
    // 3. 권한에 따른 쿼리 조정
    if (!permissions.overallAllowed) {
      return {
        success: false,
        error: 'Insufficient permissions',
        alternatives: permissions.recommendations
      };
    }
    
    // 4. 제한된 범위에서 쿼리 실행
    return await this.executeRestrictedQuery(query, permissions);
  }
}
```

**결론**: 현재 코드베이스를 활용하여 **Kubernetes RBAC Agent는 즉시 구현 가능**하며, **AWS IAM Agent는 기본 형태로 2주 내 구현 가능**합니다. 전체 아키텍처는 단계적으로 확장하는 것이 현실적입니다.