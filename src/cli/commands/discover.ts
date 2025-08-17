import { rbacManager } from '@core/rbac/RBACManager';
import { Logger } from '../utils/logger';
import chalk from 'chalk';
import ora from 'ora';

const logger = Logger.getInstance();

export interface DiscoverOptions {
  platform?: string;
  region?: string;
  output?: string;
  verbose?: boolean;
}

interface DiscoveredCluster {
  name: string;
  platform: string;
  region: string;
  status: string;
  accessible: boolean;
  configured: boolean;
  endpoint?: string;
  version?: string;
  nodeCount?: number;
}

/**
 * Discover command - 사용 가능한 Kubernetes 클러스터 검색
 */
export async function discoverCommand(options: DiscoverOptions): Promise<void> {
  const spinner = ora('Discovering available clusters...').start();

  try {
    await rbacManager.initialize();
    
    // 플랫폼별 클러스터 검색
    const clusters: DiscoveredCluster[] = [];
    
    if (!options.platform || options.platform === 'all') {
      // 모든 플랫폼에서 검색
      clusters.push(...await discoverKubernetesClusters());
      clusters.push(...await discoverAWSClusters(options.region));
      clusters.push(...await discoverGCPClusters(options.region));
      clusters.push(...await discoverAzureClusters(options.region));
      clusters.push(...await discoverLocalClusters());
    } else {
      // 특정 플랫폼만 검색
      switch (options.platform.toLowerCase()) {
        case 'kubernetes':
        case 'k8s':
          clusters.push(...await discoverKubernetesClusters());
          break;
        case 'aws':
        case 'eks':
          clusters.push(...await discoverAWSClusters(options.region));
          break;
        case 'gcp':
        case 'gke':
          clusters.push(...await discoverGCPClusters(options.region));
          break;
        case 'azure':
        case 'aks':
          clusters.push(...await discoverAzureClusters(options.region));
          break;
        case 'local':
          clusters.push(...await discoverLocalClusters());
          break;
        default:
          throw new Error(`Unsupported platform: ${options.platform}`);
      }
    }

    spinner.stop();

    // 결과 표시
    await displayDiscoveryResults(clusters, options);

    // 접근 가능한 클러스터 요약
    const accessibleClusters = clusters.filter(c => c.accessible);
    const configuredClusters = clusters.filter(c => c.configured);

    console.log(chalk.blue('\n📊 Discovery Summary'));
    console.log(chalk.blue('=' .repeat(60)));
    console.log(chalk.white(`Total Clusters Found: ${clusters.length}`));
    console.log(chalk.green(`Accessible Clusters: ${accessibleClusters.length}`));
    console.log(chalk.cyan(`Already Configured: ${configuredClusters.length}`));

    // 다음 단계 제안
    if (accessibleClusters.length > configuredClusters.length) {
      const unconfiguredClusters = accessibleClusters.filter(c => !c.configured);
      console.log(chalk.yellow('\n💡 To connect to unconfigured clusters:'));
      unconfiguredClusters.slice(0, 3).forEach(cluster => {
        console.log(chalk.yellow(`   a2a connect ${cluster.name}`));
      });
    }

  } catch (error) {
    spinner.fail('Failed to discover clusters');
    logger.error(`❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * 현재 구성된 Kubernetes 컨텍스트 검색
 */
async function discoverKubernetesClusters(): Promise<DiscoveredCluster[]> {
  const clusters: DiscoveredCluster[] = [];
  
  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);

    // 모든 컨텍스트 가져오기
    const { stdout } = await execAsync('kubectl config get-contexts -o name');
    const contexts = stdout.trim().split('\n').filter(ctx => ctx.length > 0);

    for (const context of contexts) {
      try {
        // 컨텍스트 전환 후 클러스터 정보 확인
        await execAsync(`kubectl config use-context ${context}`);
        
        const clusterInfo = await getClusterInfo(context);
        clusters.push({
          name: context,
          platform: 'kubernetes',
          region: clusterInfo.region || 'unknown',
          status: clusterInfo.status,
          accessible: clusterInfo.accessible,
          configured: true, // kubeconfig에 있으므로 구성됨
          endpoint: clusterInfo.endpoint,
          version: clusterInfo.version,
          nodeCount: clusterInfo.nodeCount
        });
      } catch (error) {
        clusters.push({
          name: context,
          platform: 'kubernetes',
          region: 'unknown',
          status: 'error',
          accessible: false,
          configured: true
        });
      }
    }
  } catch (error) {
    // kubectl이 없거나 설정이 없는 경우
  }

  return clusters;
}

/**
 * AWS EKS 클러스터 검색
 */
async function discoverAWSClusters(region?: string): Promise<DiscoveredCluster[]> {
  const clusters: DiscoveredCluster[] = [];

  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);

    // AWS CLI 사용 가능 여부 확인
    await execAsync('aws --version');
    await execAsync('aws sts get-caller-identity');

    // 리전 목록 (지정된 리전이 있으면 해당 리전만, 없으면 주요 리전들)
    const regions = region ? [region] : ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-northeast-1'];

    for (const currentRegion of regions) {
      try {
        const { stdout } = await execAsync(`aws eks list-clusters --region ${currentRegion} --output json`);
        const response = JSON.parse(stdout);

        for (const clusterName of response.clusters || []) {
          try {
            const { stdout: clusterDetail } = await execAsync(
              `aws eks describe-cluster --name ${clusterName} --region ${currentRegion} --output json`
            );
            const clusterInfo = JSON.parse(clusterDetail).cluster;

            // kubeconfig에 구성되어 있는지 확인
            const configured = await isClusterConfigured(clusterName, currentRegion);

            clusters.push({
              name: clusterName,
              platform: 'aws-eks',
              region: currentRegion,
              status: clusterInfo.status.toLowerCase(),
              accessible: clusterInfo.status === 'ACTIVE',
              configured,
              endpoint: clusterInfo.endpoint,
              version: clusterInfo.version,
              nodeCount: await getEKSNodeCount(clusterName, currentRegion)
            });
          } catch (error) {
            clusters.push({
              name: clusterName,
              platform: 'aws-eks',
              region: currentRegion,
              status: 'error',
              accessible: false,
              configured: false
            });
          }
        }
      } catch (error) {
        // 이 리전에서는 접근 불가 또는 클러스터 없음
      }
    }
  } catch (error) {
    // AWS CLI 없거나 인증 실패
  }

  return clusters;
}

/**
 * GCP GKE 클러스터 검색
 */
async function discoverGCPClusters(region?: string): Promise<DiscoveredCluster[]> {
  const clusters: DiscoveredCluster[] = [];

  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);

    // gcloud CLI 사용 가능 여부 확인
    await execAsync('gcloud version');
    await execAsync('gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -1');

    const regionFilter = region ? `--filter="zone:${region}*"` : '';
    const { stdout } = await execAsync(`gcloud container clusters list --format=json ${regionFilter}`);
    const gkeClusters = JSON.parse(stdout);

    for (const cluster of gkeClusters) {
      const configured = await isClusterConfigured(cluster.name, cluster.zone || cluster.location);

      clusters.push({
        name: cluster.name,
        platform: 'gcp-gke',
        region: cluster.zone || cluster.location,
        status: cluster.status.toLowerCase(),
        accessible: cluster.status === 'RUNNING',
        configured,
        endpoint: cluster.endpoint,
        version: cluster.currentMasterVersion,
        nodeCount: cluster.currentNodeCount
      });
    }
  } catch (error) {
    // gcloud CLI 없거나 인증 실패
  }

  return clusters;
}

/**
 * Azure AKS 클러스터 검색
 */
async function discoverAzureClusters(region?: string): Promise<DiscoveredCluster[]> {
  const clusters: DiscoveredCluster[] = [];

  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);

    // Azure CLI 사용 가능 여부 확인
    await execAsync('az version');
    await execAsync('az account show');

    const locationFilter = region ? `--query "[?location=='${region}']"` : '';
    const { stdout } = await execAsync(`az aks list --output json ${locationFilter}`);
    const aksClusters = JSON.parse(stdout);

    for (const cluster of aksClusters) {
      const configured = await isClusterConfigured(cluster.name, cluster.resourceGroup);

      clusters.push({
        name: cluster.name,
        platform: 'azure-aks',
        region: cluster.location,
        status: cluster.powerState?.code?.toLowerCase() || 'unknown',
        accessible: cluster.powerState?.code === 'Running',
        configured,
        endpoint: cluster.fqdn,
        version: cluster.kubernetesVersion,
        nodeCount: cluster.agentPoolProfiles?.reduce((sum: number, pool: any) => sum + pool.count, 0) || 0
      });
    }
  } catch (error) {
    // Azure CLI 없거나 인증 실패
  }

  return clusters;
}

/**
 * 로컬 Kubernetes 클러스터 검색
 */
async function discoverLocalClusters(): Promise<DiscoveredCluster[]> {
  const clusters: DiscoveredCluster[] = [];

  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);

    // minikube 클러스터 확인
    try {
      const { stdout: minikubeStatus } = await execAsync('minikube status --format=json');
      const status = JSON.parse(minikubeStatus);
      
      clusters.push({
        name: 'minikube',
        platform: 'local-minikube',
        region: 'local',
        status: status.Host?.toLowerCase() || 'unknown',
        accessible: status.Host === 'Running',
        configured: await isClusterConfigured('minikube', 'local')
      });
    } catch {
      // minikube 없음
    }

    // kind 클러스터 확인
    try {
      const { stdout: kindClusters } = await execAsync('kind get clusters');
      const clusters_list = kindClusters.trim().split('\n').filter(name => name.length > 0);
      
      for (const clusterName of clusters_list) {
        clusters.push({
          name: clusterName,
          platform: 'local-kind',
          region: 'local',
          status: 'running',
          accessible: true,
          configured: await isClusterConfigured(`kind-${clusterName}`, 'local')
        });
      }
    } catch {
      // kind 없음
    }

    // k3s 클러스터 확인
    try {
      await execAsync('k3s --version');
      const { stdout: k3sStatus } = await execAsync('systemctl is-active k3s');
      
      if (k3sStatus.trim() === 'active') {
        clusters.push({
          name: 'k3s',
          platform: 'local-k3s',
          region: 'local',
          status: 'running',
          accessible: true,
          configured: await isClusterConfigured('k3s', 'local')
        });
      }
    } catch {
      // k3s 없음
    }

    // Docker Desktop Kubernetes 확인
    try {
      const { stdout: dockerDesktop } = await execAsync('kubectl config get-contexts docker-desktop');
      
      clusters.push({
        name: 'docker-desktop',
        platform: 'local-docker',
        region: 'local',
        status: 'running',
        accessible: true,
        configured: true // kubectl config에서 찾았으므로 구성됨
      });
    } catch {
      // Docker Desktop Kubernetes 없음
    }

  } catch (error) {
    // 로컬 클러스터 검색 실패
  }

  return clusters;
}

/**
 * 클러스터 정보 조회
 */
async function getClusterInfo(context: string): Promise<any> {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const execAsync = promisify(exec);

  try {
    // 클러스터 연결 테스트
    await execAsync(`kubectl cluster-info --context=${context} --request-timeout=5s`);
    
    // 클러스터 상세 정보
    const { stdout: clusterInfo } = await execAsync(`kubectl cluster-info --context=${context}`);
    const { stdout: version } = await execAsync(`kubectl version --context=${context} --short --client=false | grep "Server Version" || echo "Unknown"`);
    const { stdout: nodes } = await execAsync(`kubectl get nodes --context=${context} --no-headers | wc -l || echo "0"`);

    return {
      status: 'active',
      accessible: true,
      endpoint: clusterInfo.match(/https?:\/\/[^\s]+/)?.[0] || 'unknown',
      version: version.replace('Server Version:', '').trim() || 'unknown',
      nodeCount: parseInt(nodes.trim()) || 0,
      region: extractRegionFromContext(context)
    };
  } catch (error) {
    return {
      status: 'error',
      accessible: false,
      region: extractRegionFromContext(context)
    };
  }
}

/**
 * 클러스터가 kubeconfig에 구성되어 있는지 확인
 */
async function isClusterConfigured(clusterName: string, region: string): Promise<boolean> {
  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);

    const { stdout } = await execAsync('kubectl config get-contexts -o name');
    const contexts = stdout.trim().split('\n');

    // 다양한 컨텍스트 이름 패턴 확인
    const patterns = [
      clusterName,
      `arn:aws:eks:${region}:*:cluster/${clusterName}`,
      `gke_*_${region}_${clusterName}`,
      `${clusterName}-${region}`,
      `kind-${clusterName}`,
      `docker-desktop`
    ];

    return patterns.some(pattern => 
      contexts.some(context => 
        context.includes(clusterName) || 
        context.match(pattern.replace('*', '.*'))
      )
    );
  } catch {
    return false;
  }
}

/**
 * EKS 클러스터 노드 수 조회
 */
async function getEKSNodeCount(clusterName: string, region: string): Promise<number> {
  try {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);

    const { stdout } = await execAsync(
      `aws eks list-nodegroups --cluster-name ${clusterName} --region ${region} --output json`
    );
    const nodegroups = JSON.parse(stdout);

    let totalNodes = 0;
    for (const nodegroup of nodegroups.nodegroups || []) {
      const { stdout: ngDetail } = await execAsync(
        `aws eks describe-nodegroup --cluster-name ${clusterName} --nodegroup-name ${nodegroup} --region ${region} --output json`
      );
      const ngInfo = JSON.parse(ngDetail);
      totalNodes += ngInfo.nodegroup?.scalingConfig?.currentSize || 0;
    }

    return totalNodes;
  } catch {
    return 0;
  }
}

/**
 * 컨텍스트에서 리전 추출
 */
function extractRegionFromContext(context: string): string {
  const regionPatterns = [
    /us-east-\d+/,
    /us-west-\d+/,
    /eu-west-\d+/,
    /eu-central-\d+/,
    /ap-southeast-\d+/,
    /ap-northeast-\d+/
  ];

  for (const pattern of regionPatterns) {
    const match = context.match(pattern);
    if (match) {
      return match[0];
    }
  }

  return 'unknown';
}

/**
 * 검색 결과 표시
 */
async function displayDiscoveryResults(clusters: DiscoveredCluster[], options: DiscoverOptions): Promise<void> {
  if (clusters.length === 0) {
    console.log(chalk.yellow('\n🔍 No clusters found'));
    console.log(chalk.gray('Try running with different platform or region options'));
    return;
  }

  console.log(chalk.blue('\n🔍 Discovered Clusters'));
  console.log(chalk.blue('=' .repeat(80)));

  // 플랫폼별로 그룹화
  const platformGroups = clusters.reduce((groups, cluster) => {
    const platform = cluster.platform;
    if (!groups[platform]) {
      groups[platform] = [];
    }
    groups[platform].push(cluster);
    return groups;
  }, {} as { [platform: string]: DiscoveredCluster[] });

  for (const [platform, platformClusters] of Object.entries(platformGroups)) {
    console.log(chalk.cyan(`\n📦 ${platform.toUpperCase()}`));
    console.log(chalk.gray('-'.repeat(40)));

    for (const cluster of platformClusters) {
      const statusIcon = cluster.accessible ? '✅' : 
                        cluster.status === 'error' ? '❌' : '⚠️';
      const configIcon = cluster.configured ? '🔧' : '⚙️';
      
      console.log(`${statusIcon}${configIcon} ${chalk.white(cluster.name)}`);
      console.log(chalk.gray(`     Region: ${cluster.region}`));
      console.log(chalk.gray(`     Status: ${cluster.status.toUpperCase()}`));
      
      if (cluster.version) {
        console.log(chalk.gray(`     Version: ${cluster.version}`));
      }
      
      if (cluster.nodeCount !== undefined) {
        console.log(chalk.gray(`     Nodes: ${cluster.nodeCount}`));
      }
      
      if (cluster.endpoint && options.verbose) {
        console.log(chalk.gray(`     Endpoint: ${cluster.endpoint}`));
      }

      if (!cluster.configured && cluster.accessible) {
        console.log(chalk.yellow(`     💡 Connect: a2a connect ${cluster.name}`));
      }
      
      console.log(); // 빈 줄
    }
  }

  // JSON 출력 옵션
  if (options.output === 'json') {
    console.log('\n' + JSON.stringify(clusters, null, 2));
  }
}