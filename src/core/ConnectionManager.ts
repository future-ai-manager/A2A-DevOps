import { EventEmitter } from 'events';
import { KubernetesClient, ClusterInfo } from './KubernetesClient';
import axios from 'axios';
import { existsSync } from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';
import { ShellUtils } from '../cli/utils/shell';

const execAsync = promisify(exec);

export interface ConnectionStatus {
  component: 'kubernetes' | 'falco' | 'prometheus' | 'alertmanager';
  status: 'connected' | 'degraded' | 'unavailable' | 'not_configured';
  details: {
    version?: string;
    endpoint?: string;
    cluster?: string;
    namespace?: string;
    lastCheck: string;
    error?: string;
    limitations?: string[];
  };
}

export interface EnvironmentStatus {
  overall: 'ready' | 'partial' | 'not_ready';
  connections: ConnectionStatus[];
  cluster?: ClusterInfo;
  recommendations: string[];
  blockers: string[];
}

/**
 * 모든 외부 시스템과의 연결 상태를 관리하고 검증하는 중앙 관리자
 */
export class ConnectionManager extends EventEmitter {
  private kubernetesClient: KubernetesClient;
  private lastStatus: EnvironmentStatus | null = null;
  private checkInterval: NodeJS.Timeout | null = null;

  constructor() {
    super();
    this.kubernetesClient = new KubernetesClient();
    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    this.kubernetesClient.on('connected', (info) => {
      this.emit('clusterConnected', info);
    });

    this.kubernetesClient.on('error', (error) => {
      this.emit('clusterError', error);
    });
  }

  /**
   * 전체 환경 상태를 종합적으로 체크
   */
  async checkEnvironmentStatus(force: boolean = false): Promise<EnvironmentStatus> {
    if (!force && this.lastStatus && this.isStatusFresh()) {
      return this.lastStatus;
    }

    const connections: ConnectionStatus[] = [];
    const blockers: string[] = [];
    const recommendations: string[] = [];

    // 1. Kubernetes 연결 체크
    const k8sStatus = await this.checkKubernetesConnection();
    connections.push(k8sStatus);

    if (k8sStatus.status === 'unavailable' || k8sStatus.status === 'not_configured') {
      blockers.push('Kubernetes cluster not accessible - Cannot monitor containerized workloads');
    }

    // 2. Falco 체크 (보안 모니터링)
    const falcoStatus = await this.checkFalcoConnection();
    connections.push(falcoStatus);

    if (falcoStatus.status === 'unavailable') {
      recommendations.push('Install Falco for security monitoring capabilities');
    }

    // 3. Prometheus 체크 (메트릭)
    const prometheusStatus = await this.checkPrometheusConnection();
    connections.push(prometheusStatus);

    if (prometheusStatus.status === 'unavailable') {
      recommendations.push('Install Prometheus for metrics collection');
    }

    // 4. Alertmanager 체크 (알럿)
    const alertmanagerStatus = await this.checkAlertmanagerConnection();
    connections.push(alertmanagerStatus);

    // 전체 상태 결정
    const hasBlockers = blockers.length > 0;
    const connectedCount = connections.filter(c => c.status === 'connected').length;
    const totalCount = connections.length;

    let overall: 'ready' | 'partial' | 'not_ready';
    if (hasBlockers) {
      overall = 'not_ready';
    } else if (connectedCount >= totalCount * 0.7) { // 70% 이상 연결
      overall = 'ready';
    } else {
      overall = 'partial';
    }

    // 클러스터 정보 가져오기
    let cluster: ClusterInfo | undefined;
    if (k8sStatus.status === 'connected') {
      const connectionStatus = this.kubernetesClient.getConnectionStatus();
      cluster = connectionStatus.clusters[0];
    }

    this.lastStatus = {
      overall,
      connections,
      cluster,
      recommendations,
      blockers
    };

    this.emit('statusUpdated', this.lastStatus);
    return this.lastStatus;
  }

  /**
   * Kubernetes 연결 상태 체크
   */
  private async checkKubernetesConnection(): Promise<ConnectionStatus> {
    try {
      // kubeconfig 존재 여부 체크
      const kubeconfigPaths = [
        process.env.KUBECONFIG,
        `${process.env.HOME || process.env.USERPROFILE}/.kube/config`
      ].filter(Boolean);

      const hasKubeconfig = kubeconfigPaths.some(path => path && existsSync(path));
      
      if (!hasKubeconfig) {
        return {
          component: 'kubernetes',
          status: 'not_configured',
          details: {
            lastCheck: new Date().toISOString(),
            error: 'No kubeconfig found',
            limitations: ['Cannot access any Kubernetes resources']
          }
        };
      }

      // kubectl 명령어로 연결 테스트 (크로스 플랫폼 호환)
      const { stdout: clusterInfo } = await ShellUtils.execKubectlWithTimeout('kubectl cluster-info', 10);
      
      if (!clusterInfo.includes('running at')) {
        return {
          component: 'kubernetes',
          status: 'unavailable',
          details: {
            lastCheck: new Date().toISOString(),
            error: 'Cluster not accessible',
            limitations: ['Cannot query Kubernetes resources']
          }
        };
      }

      // 현재 컨텍스트 정보 가져오기 (크로스 플랫폼 호환)
      const stderrRedirect = ShellUtils.getStderrRedirection();
      const { stdout: currentContext } = await execAsync(`kubectl config current-context ${stderrRedirect}`);
      const { stdout: currentNamespace } = await execAsync(`kubectl config view --minify --output jsonpath="{..namespace}" ${stderrRedirect}`);
      
      // 클러스터 버전 정보 (크로스 플랫폼 호환)
      const stderrRedirectForVersion = ShellUtils.getStderrRedirection();
      const grepCommand = process.platform === 'win32' ? 'findstr "Server Version"' : 'grep "Server Version"';
      const { stdout: version } = await execAsync(`kubectl version ${stderrRedirectForVersion} | ${grepCommand} || echo "Unknown"`);
      
      // 실제 연결해서 권한 테스트
      await this.kubernetesClient.connect();
      const healthCheck = await this.kubernetesClient.healthCheck();

      const status = healthCheck.status === 'healthy' ? 'connected' : 
                    healthCheck.status === 'degraded' ? 'degraded' : 'unavailable';

      return {
        component: 'kubernetes',
        status,
        details: {
          version: version.replace('Server Version: ', '').trim(),
          cluster: currentContext.trim(),
          namespace: currentNamespace.trim() || 'default',
          lastCheck: new Date().toISOString(),
          ...(status !== 'connected' && { 
            limitations: ['Limited access to cluster resources'],
            error: healthCheck.details.error 
          })
        }
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Connection failed';
      
      return {
        component: 'kubernetes',
        status: 'unavailable',
        details: {
          lastCheck: new Date().toISOString(),
          error: `클러스터에 연결되지 않음: ${errorMessage}`,
          limitations: ['Cannot access Kubernetes cluster']
        }
      };
    }
  }

  /**
   * Falco 연결 상태 체크
   */
  private async checkFalcoConnection(): Promise<ConnectionStatus> {
    try {
      // Falco 바이너리 체크
      const { stdout: version } = await execAsync('falco --version 2>/dev/null');
      
      // Falco 실행 상태 체크 (systemd)
      try {
        await execAsync('systemctl is-active falco 2>/dev/null');
        
        // 로그 파일 접근 가능 여부 체크
        const logPaths = ['/var/log/falco.log', '/var/log/syslog'];
        const accessibleLogs = [];
        
        for (const logPath of logPaths) {
          if (existsSync(logPath)) {
            accessibleLogs.push(logPath);
          }
        }

        return {
          component: 'falco',
          status: accessibleLogs.length > 0 ? 'connected' : 'degraded',
          details: {
            version: version.trim(),
            endpoint: accessibleLogs[0],
            lastCheck: new Date().toISOString(),
            ...(accessibleLogs.length === 0 && {
              limitations: ['Cannot access Falco logs - security events unavailable']
            })
          }
        };

      } catch {
        // systemd 실패 시 Docker 컨테이너로 실행 중인지 체크
        try {
          const { stdout: dockerPs } = await execAsync('docker ps --filter name=falco --quiet 2>/dev/null');
          if (dockerPs.trim()) {
            return {
              component: 'falco',
              status: 'connected',
              details: {
                version: version.trim(),
                endpoint: 'Docker container',
                lastCheck: new Date().toISOString()
              }
            };
          }
        } catch {
          // Docker도 실패
        }

        return {
          component: 'falco',
          status: 'unavailable',
          details: {
            version: version.trim(),
            lastCheck: new Date().toISOString(),
            error: 'Falco not running',
            limitations: ['Security monitoring disabled']
          }
        };
      }

    } catch (error) {
      return {
        component: 'falco',
        status: 'unavailable',
        details: {
          lastCheck: new Date().toISOString(),
          error: 'Falco not installed',
          limitations: ['Security monitoring unavailable']
        }
      };
    }
  }

  /**
   * Prometheus 연결 상태 체크
   */
  private async checkPrometheusConnection(): Promise<ConnectionStatus> {
    const prometheusUrl = 'http://localhost:9090';
    
    try {
      // 헬스 체크
      const healthResponse = await axios.get(`${prometheusUrl}/-/healthy`, { timeout: 5000 });
      
      if (healthResponse.status !== 200) {
        throw new Error('Health check failed');
      }

      // 버전 정보 가져오기
      try {
        const buildInfoResponse = await axios.get(`${prometheusUrl}/api/v1/query`, {
          params: { query: 'prometheus_build_info' },
          timeout: 5000
        });
        
        const version = buildInfoResponse.data.data.result[0]?.metric?.version || 'unknown';
        
        return {
          component: 'prometheus',
          status: 'connected',
          details: {
            version,
            endpoint: prometheusUrl,
            lastCheck: new Date().toISOString()
          }
        };

      } catch {
        return {
          component: 'prometheus',
          status: 'connected',
          details: {
            version: 'unknown',
            endpoint: prometheusUrl,
            lastCheck: new Date().toISOString()
          }
        };
      }

    } catch (error) {
      // Prometheus 바이너리가 설치되어 있는지 체크
      try {
        await execAsync('prometheus --version 2>/dev/null');
        return {
          component: 'prometheus',
          status: 'unavailable',
          details: {
            lastCheck: new Date().toISOString(),
            error: 'Prometheus installed but not running',
            limitations: ['Metrics collection disabled']
          }
        };
      } catch {
        return {
          component: 'prometheus',
          status: 'unavailable',
          details: {
            lastCheck: new Date().toISOString(),
            error: 'Prometheus not installed',
            limitations: ['Metrics monitoring unavailable']
          }
        };
      }
    }
  }

  /**
   * Alertmanager 연결 상태 체크
   */
  private async checkAlertmanagerConnection(): Promise<ConnectionStatus> {
    const alertmanagerUrl = 'http://localhost:9093';
    
    try {
      const response = await axios.get(`${alertmanagerUrl}/api/v1/status`, { timeout: 5000 });
      
      return {
        component: 'alertmanager',
        status: 'connected',
        details: {
          endpoint: alertmanagerUrl,
          lastCheck: new Date().toISOString()
        }
      };

    } catch (error) {
      return {
        component: 'alertmanager',
        status: 'unavailable',
        details: {
          lastCheck: new Date().toISOString(),
          error: 'Alertmanager not accessible',
          limitations: ['Alert management disabled']
        }
      };
    }
  }

  /**
   * 특정 컴포넌트가 사용 가능한지 체크
   */
  async isComponentAvailable(component: 'kubernetes' | 'falco' | 'prometheus' | 'alertmanager'): Promise<boolean> {
    const status = await this.checkEnvironmentStatus();
    const componentStatus = status.connections.find(c => c.component === component);
    return componentStatus?.status === 'connected';
  }

  /**
   * 쿼리 실행 전 필수 컴포넌트 체크
   */
  async validateQueryPrerequisites(requiredComponents: string[]): Promise<{
    canProceed: boolean;
    blockers: string[];
    warnings: string[];
  }> {
    const status = await this.checkEnvironmentStatus();
    const blockers: string[] = [];
    const warnings: string[] = [];

    for (const component of requiredComponents) {
      const componentStatus = status.connections.find(c => c.component === component);
      
      if (!componentStatus || componentStatus.status === 'unavailable') {
        blockers.push(`${component} is not available - ${componentStatus?.details.error || 'Service not accessible'}`);
      } else if (componentStatus.status === 'degraded') {
        warnings.push(`${component} has limited functionality - ${componentStatus.details.limitations?.join(', ') || 'Degraded performance'}`);
      }
    }

    return {
      canProceed: blockers.length === 0,
      blockers,
      warnings
    };
  }

  /**
   * 주기적 상태 모니터링 시작
   */
  startMonitoring(intervalMs: number = 30000): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }

    this.checkInterval = setInterval(async () => {
      try {
        await this.checkEnvironmentStatus(true);
      } catch (error) {
        this.emit('monitoringError', error);
      }
    }, intervalMs);
  }

  /**
   * 모니터링 중지
   */
  stopMonitoring(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
  }

  /**
   * 환경 설정 가이드 생성
   */
  generateSetupGuide(): string[] {
    const guide: string[] = [];

    if (!this.lastStatus) {
      guide.push('Run health check first: a2a doctor');
      return guide;
    }

    const unavailableComponents = this.lastStatus.connections.filter(c => 
      c.status === 'unavailable' || c.status === 'not_configured'
    );

    for (const component of unavailableComponents) {
      switch (component.component) {
        case 'kubernetes':
          guide.push('Kubernetes Setup:');
          guide.push('  1. Install kubectl: https://kubernetes.io/docs/tasks/tools/');
          guide.push('  2. Configure cluster access (kubeconfig)');
          guide.push('  3. Test: kubectl cluster-info');
          break;

        case 'falco':
          guide.push('Falco Setup:');
          guide.push('  1. Install: curl -s https://falco.org/script/install | bash');
          guide.push('  2. Start: sudo systemctl start falco');
          guide.push('  3. Verify: sudo systemctl status falco');
          break;

        case 'prometheus':
          guide.push('Prometheus Setup:');
          guide.push('  1. Download: https://prometheus.io/download/');
          guide.push('  2. Configure: prometheus.yml');
          guide.push('  3. Start: ./prometheus --config.file=prometheus.yml');
          break;

        case 'alertmanager':
          guide.push('Alertmanager Setup:');
          guide.push('  1. Download: https://prometheus.io/download/');
          guide.push('  2. Configure: alertmanager.yml');
          guide.push('  3. Start: ./alertmanager --config.file=alertmanager.yml');
          break;
      }
      guide.push('');
    }

    return guide;
  }

  private isStatusFresh(): boolean {
    if (!this.lastStatus) return false;
    
    const oldestCheck = Math.min(
      ...this.lastStatus.connections.map(c => new Date(c.details.lastCheck).getTime())
    );
    
    return Date.now() - oldestCheck < 60000; // 1분 이내면 fresh
  }

  async disconnect(): Promise<void> {
    this.stopMonitoring();
    await this.kubernetesClient.disconnect();
    this.lastStatus = null;
  }

  getLastStatus(): EnvironmentStatus | null {
    return this.lastStatus;
  }
}