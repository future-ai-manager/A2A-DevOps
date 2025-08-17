import { EventEmitter } from 'events';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as https from 'https';
import { URL } from 'url';
import { ShellUtils } from '../cli/utils/shell';

const execAsync = promisify(exec);

export interface KubeConfig {
  server: string;
  token?: string;
  certificate?: string;
  namespace: string;
  context: string;
  user: string;
}

export interface ClusterInfo {
  name: string;
  server: string;
  version: string;
  nodeCount: number;
  namespaces: string[];
  rbacEnabled: boolean;
}

/**
 * Kubernetes API 직접 연결 클라이언트
 * kubeconfig 자동 감지 및 다중 클러스터 지원
 */
export class KubernetesClient extends EventEmitter {
  private kubeConfig: KubeConfig | null = null;
  private isConnected: boolean = false;
  private clusters: Map<string, ClusterInfo> = new Map();
  private currentContext: string | null = null;

  constructor() {
    super();
    this.setMaxListeners(50);
  }

  /**
   * Kubernetes 클러스터에 연결
   */
  async connect(): Promise<boolean> {
    try {
      // 1. kubeconfig 파일 자동 감지
      const configPath = await this.findKubeConfig();
      if (!configPath) {
        throw new Error('kubeconfig 파일을 찾을 수 없습니다');
      }

      // 2. kubeconfig 파싱
      const config = await this.parseKubeConfig(configPath);
      if (!config) {
        throw new Error('kubeconfig 파싱 실패');
      }

      this.kubeConfig = config;

      // 3. 클러스터 연결 테스트
      const connectionTest = await this.testConnection();
      if (!connectionTest) {
        throw new Error('Kubernetes API 서버에 연결할 수 없습니다');
      }

      // 4. 클러스터 정보 수집
      await this.gatherClusterInfo();

      this.isConnected = true;
      this.emit('connected', {
        server: this.kubeConfig.server,
        context: this.kubeConfig.context,
        namespace: this.kubeConfig.namespace
      });

      return true;
    } catch (error) {
      this.emit('error', error);
      return false;
    }
  }

  /**
   * kubeconfig 파일 찾기
   */
  private async findKubeConfig(): Promise<string | null> {
    const possiblePaths = [
      process.env.KUBECONFIG,
      path.join(os.homedir(), '.kube', 'config'),
      path.join(os.homedir(), '.kube', 'config.yaml'),
      '/etc/kubernetes/admin.conf',
      '/etc/rancher/k3s/k3s.yaml'
    ].filter(Boolean) as string[];

    for (const configPath of possiblePaths) {
      try {
        if (fs.existsSync(configPath)) {
          await fs.promises.access(configPath, fs.constants.R_OK);
          return configPath;
        }
      } catch (error) {
        continue;
      }
    }

    return null;
  }

  /**
   * kubeconfig 파일 파싱
   */
  private async parseKubeConfig(_configPath: string): Promise<KubeConfig | null> {
    try {
      // kubectl을 사용하여 현재 컨텍스트 정보 추출 (크로스 플랫폼 호환)
      const stderrRedirect = ShellUtils.getStderrRedirection();
      const { stdout: currentContextOutput } = await execAsync(`kubectl config current-context ${stderrRedirect}`);
      const currentContext = currentContextOutput.trim();

      if (!currentContext) {
        return null;
      }

      // 클러스터 서버 URL 추출
      const { stdout: clusterOutput } = await execAsync(`kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}' ${stderrRedirect}`);
      const server = clusterOutput.trim().replace(/^'|'$/g, ''); // Remove surrounding quotes

      // 네임스페이스 추출
      const { stdout: namespaceOutput } = await execAsync(`kubectl config view --minify --raw -o jsonpath='{.contexts[0].context.namespace}' ${stderrRedirect}`);
      const namespace = namespaceOutput.trim().replace(/^'|'$/g, '') || 'default';

      // 사용자 정보 추출
      const { stdout: userOutput } = await execAsync(`kubectl config view --minify --raw -o jsonpath='{.contexts[0].context.user}' ${stderrRedirect}`);
      const user = userOutput.trim().replace(/^'|'$/g, '');

      // 토큰 추출 시도
      let token: string | undefined;
      try {
        const { stdout: tokenOutput } = await execAsync(`kubectl config view --minify --raw -o jsonpath='{.users[0].user.token}' ${stderrRedirect}`);
        const cleanToken = tokenOutput.trim().replace(/^'|'$/g, '');
        token = cleanToken || undefined;
      } catch (tokenError) {
        // 토큰이 없을 수 있음
      }

      return {
        server,
        token,
        namespace,
        context: currentContext,
        user
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * 클러스터 연결 테스트
   */
  private async testConnection(): Promise<boolean> {
    try {
      // kubectl을 사용하여 연결 테스트 (크로스 플랫폼 호환)
      await ShellUtils.execKubectlWithTimeout('kubectl cluster-info', 10);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * 클러스터 정보 수집
   */
  private async gatherClusterInfo(): Promise<void> {
    try {
      // 클러스터 버전 확인 (크로스 플랫폼 호환)
      const stderrRedirect = ShellUtils.getStderrRedirection();
      const grepCommand = process.platform === 'win32' ? 'findstr "Server Version"' : 'grep "Server Version"';
      const { stdout: versionOutput } = await execAsync(`kubectl version ${stderrRedirect} | ${grepCommand} || echo "Unknown"`);
      const version = versionOutput.replace('Server Version: ', '').trim() || 'Unknown';

      // 노드 수 확인
      const wcCommand = process.platform === 'win32' ? 'find /c /v ""' : 'wc -l';
      const { stdout: nodeOutput } = await execAsync(`kubectl get nodes --no-headers ${stderrRedirect} | ${wcCommand} || echo "0"`, { maxBuffer: 1024 * 1024 });
      const nodeCount = parseInt(nodeOutput.trim()) || 0;

      // 네임스페이스 목록
      const { stdout: namespacesOutput } = await execAsync(`kubectl get namespaces --no-headers -o custom-columns=":metadata.name" ${stderrRedirect} || echo "default"`, { maxBuffer: 1024 * 1024 });
      const namespaces = namespacesOutput.trim().split('\n').filter(ns => ns.length > 0);

      // RBAC 활성화 여부 확인
      let rbacEnabled = false;
      try {
        await execAsync(`kubectl auth can-i create pods ${stderrRedirect}`);
        rbacEnabled = true;
      } catch (rbacError) {
        rbacEnabled = false;
      }

      const clusterInfo: ClusterInfo = {
        name: this.kubeConfig!.context,
        server: this.kubeConfig!.server,
        version,
        nodeCount,
        namespaces,
        rbacEnabled
      };

      this.clusters.set(this.kubeConfig!.context, clusterInfo);
      this.currentContext = this.kubeConfig!.context;

      this.emit('clusterInfo', clusterInfo);
    } catch (error) {
      this.emit('error', `클러스터 정보 수집 실패: ${error}`);
    }
  }

  /**
   * 직접 API 호출 (kubectl 없이)
   */
  async apiCall(path: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET', body?: any): Promise<any> {
    if (!this.kubeConfig || !this.isConnected) {
      throw new Error('Kubernetes 클러스터에 연결되지 않음');
    }

    return new Promise((resolve, reject) => {
      try {
        const url = new URL(path, this.kubeConfig!.server);
        
        const headers: { [key: string]: string } = {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        };

        // 인증 헤더 추가
        if (this.kubeConfig!.token) {
          headers['Authorization'] = `Bearer ${this.kubeConfig!.token}`;
        }

        const options: https.RequestOptions = {
          hostname: url.hostname,
          port: url.port || 443,
          path: url.pathname + url.search,
          method,
          headers,
          // SSL 검증 비활성화 (개발용 - 운영에서는 제거)
          rejectUnauthorized: false
        };

        const req = https.request(options, (res) => {
          let data = '';
          res.on('data', (chunk) => data += chunk);
          res.on('end', () => {
            try {
              const result = JSON.parse(data);
              resolve(result);
            } catch (parseError) {
              resolve(data);
            }
          });
        });

        req.on('error', (error) => reject(error));

        if (body && (method === 'POST' || method === 'PUT')) {
          req.write(JSON.stringify(body));
        }

        req.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Pod 목록 조회
   */
  async getPods(namespace: string = 'default'): Promise<any[]> {
    try {
      const result = await this.apiCall(`/api/v1/namespaces/${namespace}/pods`);
      return result.items || [];
    } catch (error) {
      // API 호출 실패 시 kubectl 사용
      try {
        const { stdout } = await execAsync(`kubectl get pods -n ${namespace} -o json`);
        const result = JSON.parse(stdout);
        return result.items || [];
      } catch (kubectlError) {
        throw new Error(`Pod 목록 조회 실패: ${error}`);
      }
    }
  }

  /**
   * Secret 목록 조회
   */
  async getSecrets(namespace: string = 'default'): Promise<any[]> {
    try {
      const result = await this.apiCall(`/api/v1/namespaces/${namespace}/secrets`);
      return result.items || [];
    } catch (error) {
      // API 호출 실패 시 kubectl 사용
      try {
        const { stdout } = await execAsync(`kubectl get secrets -n ${namespace} -o json`);
        const result = JSON.parse(stdout);
        return result.items || [];
      } catch (kubectlError) {
        throw new Error(`Secret 목록 조회 실패: ${error}`);
      }
    }
  }

  /**
   * 권한 확인
   */
  async checkPermissions(): Promise<{ [action: string]: boolean }> {
    const permissions: { [action: string]: boolean } = {};
    
    const actionsToCheck = [
      'get pods',
      'list secrets',
      'create pods', 
      'delete pods',
      'get nodes',
      'list namespaces',
      'get clusterroles',
      'create deployments'
    ];

    for (const action of actionsToCheck) {
      try {
        const stderrRedirect = ShellUtils.getStderrRedirection();
        await execAsync(`kubectl auth can-i ${action} ${stderrRedirect}`);
        permissions[action] = true;
      } catch (error) {
        permissions[action] = false;
      }
    }

    return permissions;
  }

  /**
   * 다중 컨텍스트 지원
   */
  async listContexts(): Promise<string[]> {
    try {
      const stderrRedirect = ShellUtils.getStderrRedirection();
      const { stdout } = await execAsync(`kubectl config get-contexts -o name ${stderrRedirect}`);
      return stdout.trim().split('\n').filter(ctx => ctx.length > 0);
    } catch (error) {
      return [];
    }
  }

  /**
   * 컨텍스트 변경
   */
  async switchContext(context: string): Promise<boolean> {
    try {
      await execAsync(`kubectl config use-context ${context}`);
      
      // 새로운 컨텍스트로 재연결
      await this.disconnect();
      const success = await this.connect();
      
      if (success) {
        this.emit('contextSwitched', context);
      }
      
      return success;
    } catch (error) {
      this.emit('error', `컨텍스트 변경 실패: ${error}`);
      return false;
    }
  }

  /**
   * 실시간 Pod 상태 모니터링
   */
  async watchPods(namespace: string = 'default'): Promise<void> {
    try {
      // kubectl으로 Pod 상태 변경사항 실시간 모니터링
      const watchProcess = require('child_process').spawn('kubectl', [
        'get', 'pods', 
        '-n', namespace,
        '--watch', 
        '-o', 'json'
      ]);

      watchProcess.stdout.on('data', (data: Buffer) => {
        try {
          const events = data.toString().split('\n').filter(line => line.trim().length > 0);
          
          for (const event of events) {
            const podEvent = JSON.parse(event);
            this.emit('podEvent', {
              type: 'MODIFIED',
              object: podEvent,
              namespace
            });
          }
        } catch (parseError) {
          // 파싱 실패는 무시
        }
      });

      watchProcess.stderr.on('data', (data: Buffer) => {
        this.emit('error', `Pod 모니터링 오류: ${data.toString()}`);
      });

    } catch (error) {
      this.emit('error', `Pod 모니터링 시작 실패: ${error}`);
    }
  }

  /**
   * 클러스터 연결 해제
   */
  async disconnect(): Promise<void> {
    this.isConnected = false;
    this.kubeConfig = null;
    this.clusters.clear();
    this.currentContext = null;
    this.emit('disconnected');
  }

  /**
   * 연결 상태 확인
   */
  getConnectionStatus(): { 
    connected: boolean; 
    config: KubeConfig | null; 
    clusters: ClusterInfo[];
    currentContext: string | null;
  } {
    return {
      connected: this.isConnected,
      config: this.kubeConfig,
      clusters: Array.from(this.clusters.values()),
      currentContext: this.currentContext
    };
  }

  /**
   * 클러스터 헬스 체크
   */
  async healthCheck(): Promise<{ 
    status: 'healthy' | 'degraded' | 'unhealthy'; 
    details: any 
  }> {
    if (!this.isConnected) {
      return {
        status: 'unhealthy',
        details: { error: '클러스터에 연결되지 않음' }
      };
    }

    try {
      // API 서버 응답 시간 측정
      const startTime = Date.now();
      await execAsync('kubectl cluster-info --request-timeout=5s');
      const responseTime = Date.now() - startTime;

      // 노드 상태 확인
      const stderrRedirect = ShellUtils.getStderrRedirection();
      const { stdout: nodeStatus } = await execAsync(`kubectl get nodes --no-headers ${stderrRedirect} || echo "0 0"`, { maxBuffer: 1024 * 1024 });
      const nodeLines = nodeStatus.trim().split('\n').filter(line => line.length > 0);
      const totalNodes = nodeLines.length;
      const readyNodes = nodeLines.filter(line => line.includes('Ready')).length;

      const healthStatus = readyNodes === totalNodes && responseTime < 3000 ? 'healthy' : 
                          readyNodes > 0 && responseTime < 10000 ? 'degraded' : 'unhealthy';

      return {
        status: healthStatus,
        details: {
          responseTime,
          totalNodes,
          readyNodes,
          server: this.kubeConfig?.server,
          context: this.kubeConfig?.context,
          lastCheck: new Date().toISOString()
        }
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        details: { 
          error: error instanceof Error ? error.message : 'Unknown error',
          lastCheck: new Date().toISOString()
        }
      };
    }
  }
}