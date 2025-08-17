import { exec } from 'child_process';
import { promisify } from 'util';
import { RBACSubAgent, PermissionResult, QueryContext } from '../RBACOrchestrator';

const execAsync = promisify(exec);

interface AWSIdentity {
  UserId: string;
  Account: string;
  Arn: string;
  Type: 'User' | 'AssumedRole' | 'Root';
}

interface EKSClusterInfo {
  name: string;
  region: string;
  status: string;
  endpoint: string;
  accessible: boolean;
}

interface AWSPermissionCheck {
  action: string;
  resource: string;
  allowed: boolean;
  details?: any;
}

/**
 * AWS IAM 전담 SubAgent
 * EKS 클러스터 접근 권한과 AWS 리소스 권한을 관리
 */
export class AWSIAMAgent extends RBACSubAgent {
  public readonly platform = 'aws';
  private awsIdentity: AWSIdentity | null = null;
  private availableClusters: EKSClusterInfo[] = [];
  private permissionCache: Map<string, { result: boolean; timestamp: number }> = new Map();
  private readonly CACHE_TTL = 300000; // 5분

  constructor() {
    super();
  }

  /**
   * AWS 연결 및 인증 상태 확인
   */
  async validateConnection(): Promise<boolean> {
    try {
      // AWS CLI 설치 확인
      await execAsync('aws --version');
      
      // AWS 인증 상태 확인
      const identity = await this.getAWSIdentity();
      
      if (identity) {
        this.awsIdentity = identity;
        return true;
      }
      
      return false;
    } catch (error) {
      this.emit('error', `AWS connection failed: ${error.message}`);
      return false;
    }
  }

  /**
   * AWS IAM 권한 확인
   */
  async checkPermissions(context: QueryContext): Promise<PermissionResult> {
    try {
      // 1. AWS 인증 상태 재확인
      if (!this.awsIdentity) {
        await this.validateConnection();
      }

      if (!this.awsIdentity) {
        return this.createUnauthenticatedResult();
      }

      // 2. EKS 클러스터 접근 권한 확인
      const eksPermissions = await this.checkEKSPermissions(context);

      // 3. 기본 AWS 서비스 권한 확인
      const awsServicePermissions = await this.checkAWSServicePermissions();

      // 4. 클러스터별 세부 권한 확인
      const clusterSpecificPermissions = await this.checkClusterSpecificPermissions(context);

      const allowed = eksPermissions.allowed && awsServicePermissions.allowed;

      return {
        platform: this.platform,
        allowed,
        roles: await this.getUserRoles(this.awsIdentity.Arn),
        restrictions: {
          namespaces: [], // AWS IAM은 K8s 네임스페이스 제한 없음
          resources: this.getAccessibleAWSResources(awsServicePermissions.details),
          verbs: this.getAllowedAWSActions(eksPermissions.details)
        },
        details: {
          identity: this.awsIdentity,
          eksPermissions: eksPermissions.details,
          awsServicePermissions: awsServicePermissions.details,
          clusterPermissions: clusterSpecificPermissions,
          availableClusters: this.availableClusters,
          checkedAt: new Date().toISOString()
        },
        suggestions: allowed ? [] : this.generateAWSPermissionSuggestions(eksPermissions, awsServicePermissions)
      };
    } catch (error) {
      return {
        platform: this.platform,
        allowed: false,
        roles: [],
        error: error.message,
        suggestions: [
          'Check AWS CLI installation: aws --version',
          'Configure AWS credentials: aws configure',
          'Verify AWS authentication: aws sts get-caller-identity',
          'Check AWS region configuration: aws configure get region'
        ]
      };
    }
  }

  /**
   * AWS 신원 정보 확인
   */
  private async getAWSIdentity(): Promise<AWSIdentity | null> {
    try {
      const { stdout } = await execAsync('aws sts get-caller-identity --output json');
      const identity = JSON.parse(stdout);
      
      return {
        UserId: identity.UserId,
        Account: identity.Account,
        Arn: identity.Arn,
        Type: this.determineIdentityType(identity.Arn)
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * ARN에서 신원 타입 결정
   */
  private determineIdentityType(arn: string): 'User' | 'AssumedRole' | 'Root' {
    if (arn.includes(':user/')) return 'User';
    if (arn.includes(':assumed-role/')) return 'AssumedRole';
    if (arn.includes(':root')) return 'Root';
    return 'User'; // 기본값
  }

  /**
   * EKS 관련 권한 확인
   */
  private async checkEKSPermissions(context: QueryContext): Promise<{ allowed: boolean; details: any }> {
    const eksChecks: AWSPermissionCheck[] = [];

    // 기본 EKS 권한 확인
    const basicEKSActions = [
      'eks:ListClusters',
      'eks:DescribeCluster',
      'eks:AccessKubernetesApi'
    ];

    for (const action of basicEKSActions) {
      const result = await this.checkAWSPermission(action, '*');
      eksChecks.push(result);
    }

    // EKS 클러스터 목록 가져오기 시도
    await this.updateAvailableClusters();

    // 특정 클러스터에 대한 권한 확인 (컨텍스트가 있는 경우)
    if (context.cluster) {
      const clusterArn = this.buildClusterArn(context.cluster);
      const clusterAccessCheck = await this.checkAWSPermission('eks:AccessKubernetesApi', clusterArn);
      eksChecks.push(clusterAccessCheck);
    }

    const allowed = eksChecks.filter(check => check.allowed).length >= 2; // 최소 2개 권한 필요

    return {
      allowed,
      details: {
        checks: eksChecks,
        availableClusters: this.availableClusters.length,
        hasClusterAccess: eksChecks.some(check => 
          check.action === 'eks:AccessKubernetesApi' && check.allowed
        )
      }
    };
  }

  /**
   * AWS 서비스 권한 확인
   */
  private async checkAWSServicePermissions(): Promise<{ allowed: boolean; details: any }> {
    const serviceChecks: AWSPermissionCheck[] = [];

    // 기본 AWS 서비스 권한
    const basicActions = [
      'sts:GetCallerIdentity',
      'iam:GetUser',
      'iam:ListAttachedUserPolicies'
    ];

    for (const action of basicActions) {
      const result = await this.checkAWSPermission(action, '*');
      serviceChecks.push(result);
    }

    const allowed = serviceChecks.some(check => check.allowed); // 최소 1개라도 허용

    return {
      allowed,
      details: {
        checks: serviceChecks,
        identityType: this.awsIdentity?.Type,
        account: this.awsIdentity?.Account
      }
    };
  }

  /**
   * AWS 권한 확인 (IAM Policy Simulator 대신 실제 API 호출로 확인)
   */
  private async checkAWSPermission(action: string, resource: string): Promise<AWSPermissionCheck> {
    const cacheKey = `${action}:${resource}`;
    
    // 캐시 확인
    const cached = this.permissionCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < this.CACHE_TTL) {
      return {
        action,
        resource,
        allowed: cached.result
      };
    }

    let allowed = false;
    let details: any = {};

    try {
      // 실제 API 호출로 권한 확인
      switch (action) {
        case 'eks:ListClusters':
          await execAsync('aws eks list-clusters --output json');
          allowed = true;
          break;
          
        case 'eks:DescribeCluster':
          // 첫 번째 클러스터에 대해 describe 시도
          if (this.availableClusters.length > 0) {
            await execAsync(`aws eks describe-cluster --name ${this.availableClusters[0].name} --output json`);
            allowed = true;
          }
          break;
          
        case 'sts:GetCallerIdentity':
          await execAsync('aws sts get-caller-identity --output json');
          allowed = true;
          break;
          
        case 'iam:GetUser':
          try {
            await execAsync('aws iam get-user --output json');
            allowed = true;
          } catch {
            // AssumedRole의 경우 GetUser가 실패할 수 있음
            allowed = this.awsIdentity?.Type === 'AssumedRole';
          }
          break;
          
        default:
          // 기본적으로 권한이 있다고 가정 (실제 사용 시점에서 확인)
          allowed = true;
      }
    } catch (error) {
      allowed = false;
      details.error = error.message;
    }

    // 캐시 저장
    this.permissionCache.set(cacheKey, {
      result: allowed,
      timestamp: Date.now()
    });

    return {
      action,
      resource,
      allowed,
      details
    };
  }

  /**
   * 사용 가능한 EKS 클러스터 목록 업데이트
   */
  private async updateAvailableClusters(): Promise<void> {
    try {
      const { stdout } = await execAsync('aws eks list-clusters --output json');
      const response = JSON.parse(stdout);
      
      const clusters: EKSClusterInfo[] = [];
      
      for (const clusterName of response.clusters || []) {
        try {
          const { stdout: clusterDetail } = await execAsync(
            `aws eks describe-cluster --name ${clusterName} --output json`
          );
          const clusterInfo = JSON.parse(clusterDetail).cluster;
          
          clusters.push({
            name: clusterName,
            region: this.getCurrentRegion(),
            status: clusterInfo.status,
            endpoint: clusterInfo.endpoint,
            accessible: clusterInfo.status === 'ACTIVE'
          });
        } catch {
          // 이 클러스터는 접근 불가
          clusters.push({
            name: clusterName,
            region: this.getCurrentRegion(),
            status: 'INACCESSIBLE',
            endpoint: '',
            accessible: false
          });
        }
      }
      
      this.availableClusters = clusters;
    } catch (error) {
      this.availableClusters = [];
    }
  }

  /**
   * 현재 AWS 리전 확인
   */
  private getCurrentRegion(): string {
    try {
      // AWS_REGION 환경변수 확인
      if (process.env.AWS_REGION) {
        return process.env.AWS_REGION;
      }
      
      // aws configure에서 region 확인 (동기적으로는 어려우므로 기본값)
      return 'us-east-1'; // 기본값
    } catch {
      return 'us-east-1';
    }
  }

  /**
   * 클러스터별 세부 권한 확인
   */
  private async checkClusterSpecificPermissions(context: QueryContext): Promise<any> {
    if (!context.cluster) {
      return {};
    }

    try {
      // 특정 클러스터의 kubeconfig 업데이트 권한 확인
      const clusterName = this.extractClusterName(context.cluster);
      const region = this.getCurrentRegion();
      
      const updateKubeconfigCheck = await this.testKubeconfigUpdate(clusterName, region);
      
      return {
        cluster: clusterName,
        region,
        canUpdateKubeconfig: updateKubeconfigCheck,
        hasClusterAccess: this.availableClusters.some(c => c.name === clusterName && c.accessible)
      };
    } catch (error) {
      return {
        error: error.message
      };
    }
  }

  /**
   * kubeconfig 업데이트 테스트 (실제로는 실행하지 않고 dry-run)
   */
  private async testKubeconfigUpdate(clusterName: string, region: string): Promise<boolean> {
    try {
      // 실제로는 kubeconfig를 업데이트하지 않고 권한만 확인
      await execAsync(`aws eks describe-cluster --name ${clusterName} --region ${region} --output json`);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * 클러스터 이름 추출
   */
  private extractClusterName(clusterContext: string): string {
    // 다양한 형태의 클러스터 컨텍스트에서 이름 추출
    if (clusterContext.includes('arn:aws:eks:')) {
      return clusterContext.split('/').pop() || clusterContext;
    }
    
    return clusterContext;
  }

  /**
   * 클러스터 ARN 구성
   */
  private buildClusterArn(clusterName: string): string {
    const region = this.getCurrentRegion();
    const account = this.awsIdentity?.Account || '*';
    return `arn:aws:eks:${region}:${account}:cluster/${clusterName}`;
  }

  /**
   * 사용자 역할 반환
   */
  async getUserRoles(userArn: string): Promise<string[]> {
    try {
      if (this.awsIdentity?.Type === 'AssumedRole') {
        // AssumedRole에서 역할 이름 추출
        const roleMatch = userArn.match(/assumed-role\/([^\/]+)/);
        return roleMatch ? [roleMatch[1]] : ['assumed-role'];
      } else if (this.awsIdentity?.Type === 'User') {
        // IAM 사용자의 경우 연결된 정책 확인 시도
        try {
          const { stdout } = await execAsync('aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query "Arn" --output text | cut -d"/" -f2) --output json');
          const policies = JSON.parse(stdout);
          return policies.AttachedPolicies?.map((p: any) => p.PolicyName) || ['iam-user'];
        } catch {
          return ['iam-user'];
        }
      }
      
      return ['aws-user'];
    } catch {
      return ['unknown'];
    }
  }

  /**
   * 접근 가능한 AWS 리소스 추출
   */
  private getAccessibleAWSResources(servicePermissions: any): string[] {
    const resources: string[] = [];
    
    if (servicePermissions.checks) {
      for (const check of servicePermissions.checks) {
        if (check.allowed) {
          const service = check.action.split(':')[0];
          if (!resources.includes(service)) {
            resources.push(service);
          }
        }
      }
    }
    
    return resources.length > 0 ? resources : ['eks'];
  }

  /**
   * 허용된 AWS 액션 추출
   */
  private getAllowedAWSActions(eksPermissions: any): string[] {
    const actions: string[] = [];
    
    if (eksPermissions.checks) {
      for (const check of eksPermissions.checks) {
        if (check.allowed) {
          actions.push(check.action);
        }
      }
    }
    
    return actions;
  }

  /**
   * 인증되지 않은 상태의 결과
   */
  private createUnauthenticatedResult(): PermissionResult {
    return {
      platform: this.platform,
      allowed: false,
      roles: [],
      error: 'AWS not authenticated',
      suggestions: [
        'Configure AWS credentials: aws configure',
        'Set AWS environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY',
        'Use AWS SSO: aws sso login',
        'Check AWS CLI version: aws --version'
      ]
    };
  }

  /**
   * AWS 권한 제안사항 생성
   */
  private generateAWSPermissionSuggestions(
    eksPermissions: { allowed: boolean; details: any },
    servicePermissions: { allowed: boolean; details: any }
  ): string[] {
    const suggestions: string[] = [];
    
    if (!servicePermissions.allowed) {
      suggestions.push('Check basic AWS authentication and permissions');
      suggestions.push('Verify AWS credentials: aws sts get-caller-identity');
    }
    
    if (!eksPermissions.allowed) {
      suggestions.push('Add EKS permissions to your IAM user/role');
      suggestions.push('Required policies: AmazonEKSClusterPolicy, AmazonEKSWorkerNodePolicy');
      suggestions.push('Check EKS cluster permissions in AWS IAM console');
    }
    
    if (this.availableClusters.length === 0) {
      suggestions.push('Verify AWS region configuration: aws configure get region');
      suggestions.push('Check if EKS clusters exist in the current region');
    }
    
    return suggestions;
  }

  /**
   * 권한 캐시 무효화
   */
  invalidatePermissionCache(): void {
    this.permissionCache.clear();
    this.availableClusters = [];
    this.awsIdentity = null;
  }

  /**
   * 사용 가능한 EKS 클러스터 목록 반환
   */
  getAvailableClusters(): EKSClusterInfo[] {
    return this.availableClusters;
  }

  /**
   * AWS 신원 정보 반환
   */
  getAWSIdentityInfo(): AWSIdentity | null {
    return this.awsIdentity;
  }

  /**
   * kubeconfig 자동 설정 (확장 기능)
   */
  async setupKubeconfig(clusterName: string, region?: string): Promise<boolean> {
    try {
      const targetRegion = region || this.getCurrentRegion();
      
      await execAsync(`aws eks update-kubeconfig --name ${clusterName} --region ${targetRegion}`);
      
      this.emit('kubeconfigUpdated', {
        cluster: clusterName,
        region: targetRegion,
        timestamp: new Date()
      });
      
      return true;
    } catch (error) {
      this.emit('error', `Failed to setup kubeconfig for ${clusterName}: ${error.message}`);
      return false;
    }
  }
}