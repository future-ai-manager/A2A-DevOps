import { BaseTool } from '@mcp-servers/base/Tool';
import { ToolResult } from '@core/types';
import { KubernetesClient } from '@core/KubernetesClient';
import { exec } from 'child_process';
import { promisify } from 'util';
import { writeFile, readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';

const execAsync = promisify(exec);

export class DeployMonitoringStackTool extends BaseTool {
  readonly name = 'deploy_monitoring_stack';
  readonly description = 'Deploy Falco and Prometheus monitoring stack to Kubernetes cluster automatically';
  readonly inputSchema = {
    type: 'object' as const,
    properties: {
      action: {
        type: 'string',
        enum: ['deploy', 'status', 'uninstall', 'upgrade', 'configure'],
        description: 'Action to perform',
        default: 'deploy'
      },
      components: {
        type: 'array',
        items: {
          type: 'string',
          enum: ['falco', 'prometheus', 'grafana', 'alertmanager', 'all']
        },
        description: 'Components to deploy',
        default: ['falco', 'prometheus']
      },
      namespace: {
        type: 'string',
        description: 'Kubernetes namespace for deployment',
        default: 'monitoring'
      },
      method: {
        type: 'string',
        enum: ['helm', 'kubectl', 'operator'],
        description: 'Deployment method',
        default: 'helm'
      },
      falcoConfig: {
        type: 'object',
        properties: {
          grpcEnabled: { type: 'boolean', default: true },
          httpEnabled: { type: 'boolean', default: true },
          logLevel: { type: 'string', default: 'INFO' },
          rules: { type: 'array', items: { type: 'string' } }
        },
        description: 'Falco configuration options'
      },
      prometheusConfig: {
        type: 'object',
        properties: {
          retention: { type: 'string', default: '30d' },
          scrapeInterval: { type: 'string', default: '15s' },
          storageSize: { type: 'string', default: '10Gi' },
          enableRemoteWrite: { type: 'boolean', default: false }
        },
        description: 'Prometheus configuration options'
      },
      exposeServices: {
        type: 'boolean',
        description: 'Expose services via NodePort or LoadBalancer',
        default: true
      },
      dryRun: {
        type: 'boolean',
        description: 'Show what would be deployed without actually deploying',
        default: false
      }
    },
    required: []
  };

  private kubernetesClient: KubernetesClient;

  constructor() {
    super();
    this.kubernetesClient = new KubernetesClient();
  }

  async execute(params: any): Promise<ToolResult> {
    if (!this.validateParams(params)) {
      return this.createErrorResult('Invalid parameters provided');
    }

    try {
      const {
        action = 'deploy',
        components = ['falco', 'prometheus'],
        namespace = 'monitoring',
        method = 'helm',
        falcoConfig = {},
        prometheusConfig = {},
        exposeServices = true,
        dryRun = false
      } = params;

      // Check Kubernetes connectivity
      const kubeConnected = await this.kubernetesClient.connect();
      if (!kubeConnected) {
        return this.createErrorResult('Cannot connect to Kubernetes cluster. Please check your kubeconfig.');
      }

      switch (action) {
        case 'deploy':
          return await this.deployComponents(components, namespace, method, {
            falcoConfig,
            prometheusConfig,
            exposeServices,
            dryRun
          });
        
        case 'status':
          return await this.checkComponentStatus(components, namespace);
        
        case 'uninstall':
          return await this.uninstallComponents(components, namespace, method, dryRun);
        
        case 'upgrade':
          return await this.upgradeComponents(components, namespace, method, dryRun);
        
        case 'configure':
          return await this.configureComponents(components, namespace, { falcoConfig, prometheusConfig });
        
        default:
          return this.createErrorResult(`Unknown action: ${action}`);
      }

    } catch (error) {
      return this.createErrorResult(`Deployment failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async deployComponents(
    components: string[],
    namespace: string,
    method: string,
    config: any
  ): Promise<ToolResult> {
    const deploymentResults: any[] = [];
    const { dryRun } = config;

    // Create namespace if it doesn't exist
    if (!dryRun) {
      await this.ensureNamespace(namespace);
    }

    for (const component of components) {
      if (component === 'all') {
        // Deploy all components
        const allComponents = ['falco', 'prometheus', 'grafana', 'alertmanager'];
        for (const comp of allComponents) {
          const result = await this.deployComponent(comp, namespace, method, config);
          deploymentResults.push(result);
        }
      } else {
        const result = await this.deployComponent(component, namespace, method, config);
        deploymentResults.push(result);
      }
    }

    // Wait for deployments to be ready (if not dry run)
    if (!dryRun) {
      await this.waitForDeployments(deploymentResults, namespace);
    }

    return this.createSuccessResult({
      message: dryRun ? 'Deployment plan generated' : 'Monitoring stack deployed successfully',
      namespace,
      deployments: deploymentResults,
      next_steps: dryRun ? [
        'Review the deployment plan above',
        'Run without --dry-run to execute deployment'
      ] : [
        'Check deployment status: a2a query "check monitoring stack status"',
        'Access Prometheus: kubectl port-forward svc/prometheus-server 9090:80 -n monitoring',
        'View Falco logs: kubectl logs -f daemonset/falco -n monitoring'
      ]
    });
  }

  private async deployComponent(
    component: string,
    namespace: string,
    method: string,
    config: any
  ): Promise<any> {
    const { dryRun, exposeServices } = config;

    switch (component) {
      case 'falco':
        return await this.deployFalco(namespace, method, config.falcoConfig, exposeServices, dryRun);
      
      case 'prometheus':
        return await this.deployPrometheus(namespace, method, config.prometheusConfig, exposeServices, dryRun);
      
      case 'grafana':
        return await this.deployGrafana(namespace, method, exposeServices, dryRun);
      
      case 'alertmanager':
        return await this.deployAlertmanager(namespace, method, exposeServices, dryRun);
      
      default:
        throw new Error(`Unsupported component: ${component}`);
    }
  }

  private async deployFalco(
    namespace: string,
    method: string,
    falcoConfig: any,
    exposeServices: boolean,
    dryRun: boolean
  ): Promise<any> {
    const config = {
      grpcEnabled: true,
      httpEnabled: true,
      logLevel: 'INFO',
      ...falcoConfig
    };

    if (method === 'helm') {
      return await this.deployFalcoWithHelm(namespace, config, exposeServices, dryRun);
    } else {
      return await this.deployFalcoWithKubectl(namespace, config, exposeServices, dryRun);
    }
  }

  private async deployFalcoWithHelm(
    namespace: string,
    config: any,
    exposeServices: boolean,
    dryRun: boolean
  ): Promise<any> {
    try {
      // Add Falco Helm repository
      const addRepoCmd = 'helm repo add falcosecurity https://falcosecurity.github.io/charts';
      const updateRepoCmd = 'helm repo update';

      if (!dryRun) {
        await execAsync(addRepoCmd);
        await execAsync(updateRepoCmd);
      }

      // Generate Helm values
      const helmValues = this.generateFalcoHelmValues(config, exposeServices);
      const valuesFile = path.join('/tmp', 'falco-values.yaml');
      
      if (!dryRun) {
        await writeFile(valuesFile, helmValues);
      }

      // Helm install command
      const helmCmd = [
        'helm',
        dryRun ? 'install --dry-run' : 'install',
        'falco',
        'falcosecurity/falco',
        `--namespace ${namespace}`,
        '--create-namespace',
        `--values ${valuesFile}`,
        '--wait'
      ].join(' ');

      const result = await execAsync(helmCmd);

      return {
        component: 'falco',
        method: 'helm',
        status: dryRun ? 'planned' : 'deployed',
        command: helmCmd,
        output: result.stdout,
        config: config,
        services: exposeServices ? {
          grpc: `falco-grpc.${namespace}.svc.cluster.local:5060`,
          http: `falco-http.${namespace}.svc.cluster.local:8765`
        } : null
      };

    } catch (error) {
      throw new Error(`Falco Helm deployment failed: ${error}`);
    }
  }

  private async deployPrometheus(
    namespace: string,
    method: string,
    prometheusConfig: any,
    exposeServices: boolean,
    dryRun: boolean
  ): Promise<any> {
    const config = {
      retention: '30d',
      scrapeInterval: '15s',
      storageSize: '10Gi',
      ...prometheusConfig
    };

    if (method === 'helm') {
      return await this.deployPrometheusWithHelm(namespace, config, exposeServices, dryRun);
    } else {
      return await this.deployPrometheusWithKubectl(namespace, config, exposeServices, dryRun);
    }
  }

  private async deployPrometheusWithHelm(
    namespace: string,
    config: any,
    exposeServices: boolean,
    dryRun: boolean
  ): Promise<any> {
    try {
      // Add Prometheus Helm repository
      const addRepoCmd = 'helm repo add prometheus-community https://prometheus-community.github.io/helm-charts';
      const updateRepoCmd = 'helm repo update';

      if (!dryRun) {
        await execAsync(addRepoCmd);
        await execAsync(updateRepoCmd);
      }

      // Generate Helm values for kube-prometheus-stack
      const helmValues = this.generatePrometheusHelmValues(config, exposeServices);
      const valuesFile = path.join('/tmp', 'prometheus-values.yaml');
      
      if (!dryRun) {
        await writeFile(valuesFile, helmValues);
      }

      // Helm install command
      const helmCmd = [
        'helm',
        dryRun ? 'install --dry-run' : 'install',
        'prometheus',
        'prometheus-community/kube-prometheus-stack',
        `--namespace ${namespace}`,
        '--create-namespace',
        `--values ${valuesFile}`,
        '--wait'
      ].join(' ');

      const result = await execAsync(helmCmd);

      return {
        component: 'prometheus',
        method: 'helm',
        status: dryRun ? 'planned' : 'deployed',
        command: helmCmd,
        output: result.stdout,
        config: config,
        services: exposeServices ? {
          prometheus: `prometheus-server.${namespace}.svc.cluster.local:9090`,
          alertmanager: `prometheus-alertmanager.${namespace}.svc.cluster.local:9093`,
          grafana: `prometheus-grafana.${namespace}.svc.cluster.local:3000`
        } : null
      };

    } catch (error) {
      throw new Error(`Prometheus Helm deployment failed: ${error}`);
    }
  }

  private generateFalcoHelmValues(config: any, exposeServices: boolean): string {
    return `
# Falco configuration
falco:
  grpc:
    enabled: ${config.grpcEnabled}
    bind_address: "0.0.0.0:5060"
  
  http_output:
    enabled: ${config.httpEnabled}
    url: "http://0.0.0.0:8765/api/v1/events"
  
  log_level: ${config.logLevel}
  
  rules_file:
    - /etc/falco/falco_rules.yaml
    - /etc/falco/k8s_audit_rules.yaml

# Service configuration
service:
  type: ${exposeServices ? 'NodePort' : 'ClusterIP'}
  grpc:
    port: 5060
    nodePort: ${exposeServices ? '30060' : ''}
  http:
    port: 8765
    nodePort: ${exposeServices ? '30765' : ''}

# Resource configuration
resources:
  limits:
    cpu: 200m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 256Mi

# DaemonSet configuration for node-level monitoring
daemonset:
  updateStrategy:
    type: RollingUpdate
`;
  }

  private generatePrometheusHelmValues(config: any, exposeServices: boolean): string {
    return `
# Prometheus configuration
prometheus:
  prometheusSpec:
    retention: ${config.retention}
    scrapeInterval: ${config.scrapeInterval}
    
    storageSpec:
      volumeClaimTemplate:
        spec:
          accessModes: ["ReadWriteOnce"]
          resources:
            requests:
              storage: ${config.storageSize}
    
    serviceMonitorSelectorNilUsesHelmValues: false
    ruleSelectorNilUsesHelmValues: false

  service:
    type: ${exposeServices ? 'NodePort' : 'ClusterIP'}
    nodePort: ${exposeServices ? '30090' : ''}

# Grafana configuration
grafana:
  enabled: true
  service:
    type: ${exposeServices ? 'NodePort' : 'ClusterIP'}
    nodePort: ${exposeServices ? '30030' : ''}
  
  adminPassword: 'a2a-admin'

# Alertmanager configuration
alertmanager:
  enabled: true
  service:
    type: ${exposeServices ? 'NodePort' : 'ClusterIP'}
    nodePort: ${exposeServices ? '30093' : ''}

# Node exporter for system metrics
nodeExporter:
  enabled: true

# Kube-state-metrics for Kubernetes metrics
kubeStateMetrics:
  enabled: true
`;
  }

  private async ensureNamespace(namespace: string): Promise<void> {
    try {
      await execAsync(`kubectl get namespace ${namespace}`);
    } catch {
      // Namespace doesn't exist, create it
      await execAsync(`kubectl create namespace ${namespace}`);
    }
  }

  private async checkComponentStatus(components: string[], namespace: string): Promise<ToolResult> {
    const statusResults: any[] = [];

    for (const component of components) {
      const status = await this.getComponentStatus(component, namespace);
      statusResults.push(status);
    }

    return this.createSuccessResult({
      message: 'Component status retrieved',
      namespace,
      components: statusResults,
      summary: {
        total: statusResults.length,
        running: statusResults.filter(s => s.status === 'running').length,
        pending: statusResults.filter(s => s.status === 'pending').length,
        failed: statusResults.filter(s => s.status === 'failed').length
      }
    });
  }

  private async getComponentStatus(component: string, namespace: string): Promise<any> {
    try {
      switch (component) {
        case 'falco':
          const falcoStatus = await execAsync(`kubectl get daemonset falco -n ${namespace} -o json`);
          const falcoData = JSON.parse(falcoStatus.stdout);
          return {
            component: 'falco',
            status: falcoData.status.numberReady === falcoData.status.desiredNumberScheduled ? 'running' : 'pending',
            desired: falcoData.status.desiredNumberScheduled,
            ready: falcoData.status.numberReady,
            pods: await this.getPodStatus('app=falco', namespace)
          };

        case 'prometheus':
          const prometheusStatus = await execAsync(`kubectl get statefulset prometheus-prometheus -n ${namespace} -o json`);
          const prometheusData = JSON.parse(prometheusStatus.stdout);
          return {
            component: 'prometheus',
            status: prometheusData.status.readyReplicas === prometheusData.status.replicas ? 'running' : 'pending',
            replicas: prometheusData.status.replicas,
            ready: prometheusData.status.readyReplicas,
            pods: await this.getPodStatus('app.kubernetes.io/name=prometheus', namespace)
          };

        default:
          return {
            component,
            status: 'unknown',
            error: 'Component status check not implemented'
          };
      }
    } catch (error) {
      return {
        component,
        status: 'not_found',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  private async getPodStatus(selector: string, namespace: string): Promise<any[]> {
    try {
      const result = await execAsync(`kubectl get pods -l "${selector}" -n ${namespace} -o json`);
      const data = JSON.parse(result.stdout);
      
      return data.items.map((pod: any) => ({
        name: pod.metadata.name,
        status: pod.status.phase,
        ready: pod.status.containerStatuses?.every((c: any) => c.ready) || false,
        restarts: pod.status.containerStatuses?.reduce((sum: number, c: any) => sum + c.restartCount, 0) || 0
      }));
    } catch {
      return [];
    }
  }

  private async waitForDeployments(deploymentResults: any[], namespace: string): Promise<void> {
    // Wait for deployments to be ready
    for (const result of deploymentResults) {
      if (result.status === 'deployed') {
        await this.waitForComponent(result.component, namespace);
      }
    }
  }

  private async waitForComponent(component: string, namespace: string): Promise<void> {
    const maxWaitTime = 300; // 5 minutes
    const checkInterval = 10; // 10 seconds
    let waitTime = 0;

    while (waitTime < maxWaitTime) {
      const status = await this.getComponentStatus(component, namespace);
      if (status.status === 'running') {
        break;
      }
      
      await new Promise(resolve => setTimeout(resolve, checkInterval * 1000));
      waitTime += checkInterval;
    }
  }

  private async uninstallComponents(
    components: string[],
    namespace: string,
    method: string,
    dryRun: boolean
  ): Promise<ToolResult> {
    const uninstallResults: any[] = [];

    for (const component of components) {
      try {
        let result: any;
        
        if (method === 'helm') {
          result = await this.uninstallComponentWithHelm(component, namespace, dryRun);
        } else {
          result = await this.uninstallComponentWithKubectl(component, namespace, dryRun);
        }
        
        uninstallResults.push(result);
      } catch (error) {
        uninstallResults.push({
          component,
          status: 'failed',
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    return this.createSuccessResult({
      message: dryRun ? 'Uninstall plan generated' : 'Components uninstalled',
      namespace,
      uninstallResults,
      summary: {
        total: uninstallResults.length,
        successful: uninstallResults.filter(r => r.status === 'uninstalled' || r.status === 'planned').length,
        failed: uninstallResults.filter(r => r.status === 'failed').length
      }
    });
  }

  private async upgradeComponents(
    components: string[],
    namespace: string,
    method: string,
    dryRun: boolean
  ): Promise<ToolResult> {
    const upgradeResults: any[] = [];

    for (const component of components) {
      try {
        let result: any;
        
        if (method === 'helm') {
          result = await this.upgradeComponentWithHelm(component, namespace, dryRun);
        } else {
          result = await this.upgradeComponentWithKubectl(component, namespace, dryRun);
        }
        
        upgradeResults.push(result);
      } catch (error) {
        upgradeResults.push({
          component,
          status: 'failed',
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    return this.createSuccessResult({
      message: dryRun ? 'Upgrade plan generated' : 'Components upgraded',
      namespace,
      upgradeResults,
      summary: {
        total: upgradeResults.length,
        successful: upgradeResults.filter(r => r.status === 'upgraded' || r.status === 'planned').length,
        failed: upgradeResults.filter(r => r.status === 'failed').length
      }
    });
  }

  private async configureComponents(
    components: string[],
    namespace: string,
    config: any
  ): Promise<ToolResult> {
    const configureResults: any[] = [];

    for (const component of components) {
      try {
        let result: any;
        
        switch (component) {
          case 'falco':
            result = await this.configureFalco(namespace, config.falcoConfig);
            break;
          case 'prometheus':
            result = await this.configurePrometheus(namespace, config.prometheusConfig);
            break;
          default:
            result = {
              component,
              status: 'skipped',
              message: 'Configuration not supported for this component'
            };
        }
        
        configureResults.push(result);
      } catch (error) {
        configureResults.push({
          component,
          status: 'failed',
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    return this.createSuccessResult({
      message: 'Component configuration completed',
      namespace,
      configureResults,
      summary: {
        total: configureResults.length,
        successful: configureResults.filter(r => r.status === 'configured').length,
        failed: configureResults.filter(r => r.status === 'failed').length,
        skipped: configureResults.filter(r => r.status === 'skipped').length
      }
    });
  }

  private async deployFalcoWithKubectl(
    namespace: string,
    config: any,
    exposeServices: boolean,
    dryRun: boolean
  ): Promise<any> {
    try {
      // Generate Kubernetes manifests for Falco
      const manifests = this.generateFalcoKubernetesManifests(namespace, config, exposeServices);
      const manifestFile = path.join('/tmp', 'falco-deployment.yaml');
      
      if (!dryRun) {
        await writeFile(manifestFile, manifests);
      }

      // Apply manifests
      const kubectlCmd = dryRun 
        ? `kubectl apply --dry-run=client -f ${manifestFile}`
        : `kubectl apply -f ${manifestFile}`;

      const result = await execAsync(kubectlCmd);

      return {
        component: 'falco',
        method: 'kubectl',
        status: dryRun ? 'planned' : 'deployed',
        command: kubectlCmd,
        output: result.stdout,
        config: config,
        manifestFile: manifestFile,
        services: exposeServices ? {
          grpc: `falco-grpc.${namespace}.svc.cluster.local:5060`,
          http: `falco-http.${namespace}.svc.cluster.local:8765`
        } : null
      };

    } catch (error) {
      throw new Error(`Falco kubectl deployment failed: ${error}`);
    }
  }

  private async deployPrometheusWithKubectl(
    namespace: string,
    config: any,
    exposeServices: boolean,
    dryRun: boolean
  ): Promise<any> {
    try {
      // Generate Kubernetes manifests for Prometheus
      const manifests = this.generatePrometheusKubernetesManifests(namespace, config, exposeServices);
      const manifestFile = path.join('/tmp', 'prometheus-deployment.yaml');
      
      if (!dryRun) {
        await writeFile(manifestFile, manifests);
      }

      // Apply manifests
      const kubectlCmd = dryRun 
        ? `kubectl apply --dry-run=client -f ${manifestFile}`
        : `kubectl apply -f ${manifestFile}`;

      const result = await execAsync(kubectlCmd);

      return {
        component: 'prometheus',
        method: 'kubectl',
        status: dryRun ? 'planned' : 'deployed',
        command: kubectlCmd,
        output: result.stdout,
        config: config,
        manifestFile: manifestFile,
        services: exposeServices ? {
          prometheus: `prometheus-server.${namespace}.svc.cluster.local:9090`,
          alertmanager: `prometheus-alertmanager.${namespace}.svc.cluster.local:9093`
        } : null
      };

    } catch (error) {
      throw new Error(`Prometheus kubectl deployment failed: ${error}`);
    }
  }

  private async deployGrafana(
    namespace: string,
    method: string,
    exposeServices: boolean,
    dryRun: boolean
  ): Promise<any> {
    // Implementation for Grafana deployment
    return {
      component: 'grafana',
      status: 'not_implemented',
      message: 'Grafana deployment will be included in Prometheus stack'
    };
  }

  private async deployAlertmanager(
    namespace: string,
    method: string,
    exposeServices: boolean,
    dryRun: boolean
  ): Promise<any> {
    // Implementation for Alertmanager deployment
    return {
      component: 'alertmanager',
      status: 'not_implemented',
      message: 'Alertmanager deployment will be included in Prometheus stack'
    };
  }

  // Helper methods for kubectl deployments
  private generateFalcoKubernetesManifests(namespace: string, config: any, exposeServices: boolean): string {
    const serviceType = exposeServices ? 'NodePort' : 'ClusterIP';
    
    return `
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
  namespace: ${namespace}
  labels:
    app: falco
spec:
  selector:
    matchLabels:
      app: falco
  template:
    metadata:
      labels:
        app: falco
    spec:
      serviceAccountName: falco
      hostNetwork: true
      hostPID: true
      containers:
      - name: falco
        image: falcosecurity/falco:latest
        args:
          - /usr/bin/falco
          - --cri=/run/containerd/containerd.sock
          - --cri=/run/crio/crio.sock
          - -K=/var/run/secrets/kubernetes.io/serviceaccount/token
          - -k=https://kubernetes.default
          - --k8s-node=\${FALCO_K8S_NODE_NAME}
          - -pk
        env:
        - name: FALCO_K8S_NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: FALCO_GRPC_ENABLED
          value: "${config.grpcEnabled}"
        - name: FALCO_HTTP_OUTPUT_ENABLED
          value: "${config.httpEnabled}"
        - name: FALCO_LOG_LEVEL
          value: "${config.logLevel}"
        ports:
        - containerPort: 5060
          name: grpc
        - containerPort: 8765
          name: http
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /host/var/run/docker.sock
          name: docker-socket
        - mountPath: /host/dev
          name: dev-fs
        - mountPath: /host/proc
          name: proc-fs
          readOnly: true
        - mountPath: /host/boot
          name: boot-fs
          readOnly: true
        - mountPath: /host/lib/modules
          name: lib-modules
          readOnly: true
        - mountPath: /host/usr
          name: usr-fs
          readOnly: true
        - mountPath: /host/etc
          name: etc-fs
          readOnly: true
      volumes:
      - name: docker-socket
        hostPath:
          path: /var/run/docker.sock
      - name: dev-fs
        hostPath:
          path: /dev
      - name: proc-fs
        hostPath:
          path: /proc
      - name: boot-fs
        hostPath:
          path: /boot
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: usr-fs
        hostPath:
          path: /usr
      - name: etc-fs
        hostPath:
          path: /etc
      tolerations:
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: falco
  namespace: ${namespace}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: falco
rules:
- apiGroups: [""]
  resources: ["pods", "nodes", "services", "namespaces", "events"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: falco
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: falco
subjects:
- kind: ServiceAccount
  name: falco
  namespace: ${namespace}
---
apiVersion: v1
kind: Service
metadata:
  name: falco-grpc
  namespace: ${namespace}
  labels:
    app: falco
spec:
  type: ${serviceType}
  ports:
  - port: 5060
    targetPort: 5060
    name: grpc
    ${exposeServices ? 'nodePort: 30060' : ''}
  selector:
    app: falco
---
apiVersion: v1
kind: Service
metadata:
  name: falco-http
  namespace: ${namespace}
  labels:
    app: falco
spec:
  type: ${serviceType}
  ports:
  - port: 8765
    targetPort: 8765
    name: http
    ${exposeServices ? 'nodePort: 30765' : ''}
  selector:
    app: falco
`;
  }

  private generatePrometheusKubernetesManifests(namespace: string, config: any, exposeServices: boolean): string {
    const serviceType = exposeServices ? 'NodePort' : 'ClusterIP';
    
    return `
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus-server
  namespace: ${namespace}
  labels:
    app: prometheus-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus-server
  template:
    metadata:
      labels:
        app: prometheus-server
    spec:
      serviceAccountName: prometheus
      containers:
      - name: prometheus
        image: prom/prometheus:latest
        args:
          - '--config.file=/etc/prometheus/prometheus.yml'
          - '--storage.tsdb.path=/prometheus/'
          - '--web.console.templates=/etc/prometheus/consoles'
          - '--web.console.libraries=/etc/prometheus/console_libraries'
          - '--web.listen-address=0.0.0.0:9090'
          - '--web.enable-lifecycle'
          - '--storage.tsdb.retention.time=${config.retention}'
        ports:
        - containerPort: 9090
        volumeMounts:
        - name: prometheus-config
          mountPath: /etc/prometheus
        - name: prometheus-storage
          mountPath: /prometheus
      volumes:
      - name: prometheus-config
        configMap:
          name: prometheus-config
      - name: prometheus-storage
        emptyDir: {}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: prometheus
  namespace: ${namespace}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: prometheus
rules:
- apiGroups: [""]
  resources: ["nodes", "nodes/proxy", "services", "endpoints", "pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["extensions"]
  resources: ["ingresses"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: prometheus
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: prometheus
subjects:
- kind: ServiceAccount
  name: prometheus
  namespace: ${namespace}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: ${namespace}
data:
  prometheus.yml: |
    global:
      scrape_interval: ${config.scrapeInterval}
      retention: ${config.retention}
    
    scrape_configs:
    - job_name: 'prometheus'
      static_configs:
      - targets: ['localhost:9090']
    
    - job_name: 'kubernetes-pods'
      kubernetes_sd_configs:
      - role: pod
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\\\\d+)?;(\\\\d+)
        replacement: \${1}:\${2}
        target_label: __address__
      - action: labelmap
        regex: __meta_kubernetes_pod_label_(.+)
      - source_labels: [__meta_kubernetes_namespace]
        action: replace
        target_label: kubernetes_namespace
      - source_labels: [__meta_kubernetes_pod_name]
        action: replace
        target_label: kubernetes_pod_name
---
apiVersion: v1
kind: Service
metadata:
  name: prometheus-server
  namespace: ${namespace}
  labels:
    app: prometheus-server
spec:
  type: ${serviceType}
  ports:
  - port: 9090
    targetPort: 9090
    name: http
    ${exposeServices ? 'nodePort: 30090' : ''}
  selector:
    app: prometheus-server
`;
  }

  // Helper methods for uninstall operations
  private async uninstallComponentWithHelm(component: string, namespace: string, dryRun: boolean): Promise<any> {
    try {
      const helmCmd = dryRun 
        ? `helm uninstall ${component} --namespace ${namespace} --dry-run`
        : `helm uninstall ${component} --namespace ${namespace}`;

      const result = await execAsync(helmCmd);

      return {
        component,
        method: 'helm',
        status: dryRun ? 'planned' : 'uninstalled',
        command: helmCmd,
        output: result.stdout
      };
    } catch (error) {
      throw new Error(`Helm uninstall failed for ${component}: ${error}`);
    }
  }

  private async uninstallComponentWithKubectl(component: string, namespace: string, dryRun: boolean): Promise<any> {
    try {
      const kubectlCmd = dryRun 
        ? `kubectl delete all -l app=${component} --namespace ${namespace} --dry-run=client`
        : `kubectl delete all -l app=${component} --namespace ${namespace}`;

      const result = await execAsync(kubectlCmd);

      return {
        component,
        method: 'kubectl',
        status: dryRun ? 'planned' : 'uninstalled',
        command: kubectlCmd,
        output: result.stdout
      };
    } catch (error) {
      throw new Error(`kubectl uninstall failed for ${component}: ${error}`);
    }
  }

  // Helper methods for upgrade operations
  private async upgradeComponentWithHelm(component: string, namespace: string, dryRun: boolean): Promise<any> {
    try {
      let repoUpdateCmd: string;
      let upgradeCmd: string;

      switch (component) {
        case 'falco':
          repoUpdateCmd = 'helm repo update falcosecurity';
          upgradeCmd = dryRun 
            ? `helm upgrade ${component} falcosecurity/falco --namespace ${namespace} --dry-run`
            : `helm upgrade ${component} falcosecurity/falco --namespace ${namespace}`;
          break;
        case 'prometheus':
          repoUpdateCmd = 'helm repo update prometheus-community';
          upgradeCmd = dryRun 
            ? `helm upgrade ${component} prometheus-community/kube-prometheus-stack --namespace ${namespace} --dry-run`
            : `helm upgrade ${component} prometheus-community/kube-prometheus-stack --namespace ${namespace}`;
          break;
        default:
          throw new Error(`Upgrade not supported for component: ${component}`);
      }

      if (!dryRun) {
        await execAsync(repoUpdateCmd);
      }

      const result = await execAsync(upgradeCmd);

      return {
        component,
        method: 'helm',
        status: dryRun ? 'planned' : 'upgraded',
        command: upgradeCmd,
        output: result.stdout
      };
    } catch (error) {
      throw new Error(`Helm upgrade failed for ${component}: ${error}`);
    }
  }

  private async upgradeComponentWithKubectl(component: string, namespace: string, dryRun: boolean): Promise<any> {
    try {
      // For kubectl upgrades, we need to regenerate and apply manifests
      let manifests: string;
      
      switch (component) {
        case 'falco':
          manifests = this.generateFalcoKubernetesManifests(namespace, {}, false);
          break;
        case 'prometheus':
          manifests = this.generatePrometheusKubernetesManifests(namespace, {}, false);
          break;
        default:
          throw new Error(`Upgrade not supported for component: ${component}`);
      }

      const manifestFile = path.join('/tmp', `${component}-upgrade.yaml`);
      
      if (!dryRun) {
        await writeFile(manifestFile, manifests);
      }

      const kubectlCmd = dryRun 
        ? `kubectl apply --dry-run=client -f ${manifestFile}`
        : `kubectl apply -f ${manifestFile}`;

      const result = await execAsync(kubectlCmd);

      return {
        component,
        method: 'kubectl',
        status: dryRun ? 'planned' : 'upgraded',
        command: kubectlCmd,
        output: result.stdout,
        manifestFile: manifestFile
      };
    } catch (error) {
      throw new Error(`kubectl upgrade failed for ${component}: ${error}`);
    }
  }

  // Helper methods for configuration operations
  private async configureFalco(namespace: string, config: any): Promise<any> {
    try {
      // Generate new Falco configuration
      const falcoConfigMap = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-config
  namespace: ${namespace}
data:
  falco.yaml: |
    grpc:
      enabled: ${config?.grpcEnabled ?? true}
      bind_address: "0.0.0.0:5060"
    
    http_output:
      enabled: ${config?.httpEnabled ?? true}
      url: "http://0.0.0.0:8765/"
    
    log_level: ${config?.logLevel ?? 'INFO'}
    
    rules_file:
      - /etc/falco/falco_rules.yaml
      - /etc/falco/k8s_audit_rules.yaml
`;

      const configFile = path.join('/tmp', 'falco-config.yaml');
      await writeFile(configFile, falcoConfigMap);

      const result = await execAsync(`kubectl apply -f ${configFile}`);

      // Restart Falco pods to pick up new configuration
      await execAsync(`kubectl rollout restart daemonset/falco -n ${namespace}`);

      return {
        component: 'falco',
        status: 'configured',
        command: `kubectl apply -f ${configFile}`,
        output: result.stdout,
        configFile: configFile
      };
    } catch (error) {
      throw new Error(`Falco configuration failed: ${error}`);
    }
  }

  private async configurePrometheus(namespace: string, config: any): Promise<any> {
    try {
      // Generate new Prometheus configuration
      const prometheusConfigMap = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: ${namespace}
data:
  prometheus.yml: |
    global:
      scrape_interval: ${config?.scrapeInterval ?? '15s'}
      retention: ${config?.retention ?? '30d'}
    
    scrape_configs:
    - job_name: 'prometheus'
      static_configs:
      - targets: ['localhost:9090']
`;

      const configFile = path.join('/tmp', 'prometheus-config.yaml');
      await writeFile(configFile, prometheusConfigMap);

      const result = await execAsync(`kubectl apply -f ${configFile}`);

      // Restart Prometheus to pick up new configuration
      await execAsync(`kubectl rollout restart deployment/prometheus-server -n ${namespace}`);

      return {
        component: 'prometheus',
        status: 'configured',
        command: `kubectl apply -f ${configFile}`,
        output: result.stdout,
        configFile: configFile
      };
    } catch (error) {
      throw new Error(`Prometheus configuration failed: ${error}`);
    }
  }
}