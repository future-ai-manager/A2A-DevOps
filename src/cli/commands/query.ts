import { ClaudeCodeBridge } from '@core/ClaudeCodeBridge';
import { AgentRouter } from '@core/AgentRouter';
import { MCPServerManager } from '@core/MCPServerManager';
import { ConnectionManager } from '@core/ConnectionManager';
import { rbacManager } from '@core/rbac/RBACManager';
import { Logger } from '../utils/logger';
import { ConfigManager } from '../utils/config';
import { ClaudeCodeError } from '@core/error/types';
import { ClaudeErrorHandler } from '@core/error/ClaudeErrorHandler';
import chalk from 'chalk';
import ora from 'ora';
import { writeFile } from 'fs/promises';
import path from 'path';

const logger = Logger.getInstance();
const configManager = ConfigManager.getInstance();

export interface QueryOptions {
  format?: string;
  agent?: string;
  output?: string;
  timeout?: string;
  cache?: boolean;
}

export async function queryCommand(query: string, options: QueryOptions): Promise<void> {
  const spinner = ora('Initializing A2A platform...').start();
  
  try {
    // Initialize RBAC system first
    spinner.text = 'Initializing RBAC system...';
    await rbacManager.initialize();

    // Initialize core components
    const config = await configManager.getConfig();
    const claudeBridge = new ClaudeCodeBridge({
      timeout: parseInt(options.timeout || '30') * 1000,
      maxRetries: config.claudeCode?.maxRetries || 3,
      debug: process.env.A2A_DEBUG === 'true'
    });

    // Check user permissions for the query
    spinner.text = 'Checking user permissions...';
    const currentUser = await getCurrentUser();
    const permissionCheck = await rbacManager.checkQueryPermissions(currentUser, query, {
      sessionId: process.env.A2A_SESSION_ID
    });

    // Display permission status
    spinner.stop();
    console.log(chalk.blue('\n🔐 Permission Check'));
    console.log(chalk.blue('=' .repeat(60)));
    
    if (!permissionCheck.overallAllowed) {
      console.log(chalk.red('❌ Insufficient permissions for this query'));
      console.log(chalk.red(`   Resource: ${permissionCheck.platformResults[0]?.error || 'Unknown'}`));
      
      if (permissionCheck.recommendations.length > 0) {
        console.log(chalk.yellow('\n💡 Recommendations:'));
        permissionCheck.recommendations.forEach(rec => {
          console.log(chalk.yellow(`   • ${rec}`));
        });
      }
      
      if (permissionCheck.conflicts.length > 0) {
        console.log(chalk.yellow('\n⚠️ Permission Conflicts:'));
        permissionCheck.conflicts.forEach(conflict => {
          console.log(chalk.yellow(`   • ${conflict.description}`));
          console.log(chalk.gray(`     Resolution: ${conflict.resolution}`));
        });
      }
      
      process.exit(1);
    }

    console.log(chalk.green('✅ Permission granted'));
    console.log(chalk.gray(`   User: ${currentUser}`));
    console.log(chalk.gray(`   Risk Level: ${permissionCheck.riskLevel.toUpperCase()}`));
    console.log(chalk.gray(`   Allowed Resources: ${permissionCheck.resolvedPermissions.join(', ')}`));
    
    if (permissionCheck.effectiveNamespaces.length > 0) {
      console.log(chalk.gray(`   Accessible Namespaces: ${permissionCheck.effectiveNamespaces.join(', ')}`));
    }

    // Check environment status
    spinner.text = 'Checking environment status...';
    const connectionManager = new ConnectionManager();
    const environmentStatus = await connectionManager.checkEnvironmentStatus();
    
    // Display environment status
    spinner.stop();
    console.log(chalk.blue('\\n🔍 Environment Status Check'));
    console.log(chalk.blue('=' .repeat(60)));
    
    for (const connection of environmentStatus.connections) {
      const statusIcon = connection.status === 'connected' ? '✅' : 
                        connection.status === 'degraded' ? '⚠️' : 
                        connection.status === 'not_configured' ? '⚙️' : '❌';
      
      const statusColor = connection.status === 'connected' ? chalk.green : 
                         connection.status === 'degraded' ? chalk.yellow : chalk.red;
      
      console.log(`${statusIcon} ${connection.component}: ${statusColor(connection.status.toUpperCase())}`);
      
      if (connection.details.cluster) {
        console.log(`   Cluster: ${chalk.cyan(connection.details.cluster)}`);
      }
      if (connection.details.namespace) {
        console.log(`   Namespace: ${chalk.cyan(connection.details.namespace)}`);
      }
      if (connection.details.endpoint) {
        console.log(`   Endpoint: ${chalk.gray(connection.details.endpoint)}`);
      }
      if (connection.details.error) {
        console.log(`   Error: ${chalk.red(connection.details.error)}`);
      }
    }
    
    // Show blockers if any
    if (environmentStatus.blockers.length > 0) {
      console.log(chalk.red('\\n🚫 Blockers:'));
      environmentStatus.blockers.forEach(blocker => {
        console.log(chalk.red(`   • ${blocker}`));
      });
      
      console.log(chalk.yellow('\\n💡 Quick fixes:'));
      console.log(chalk.gray('   • Run: a2a doctor --fix'));
      console.log(chalk.gray('   • Run: a2a setup --guide'));
      
      process.exit(1);
    }
    
    // Show warnings if any
    if (environmentStatus.recommendations.length > 0) {
      console.log(chalk.yellow('\\n⚠️ Recommendations:'));
      environmentStatus.recommendations.forEach(rec => {
        console.log(chalk.yellow(`   • ${rec}`));
      });
    }
    
    console.log(chalk.blue('=' .repeat(60)));
    
    // Check Claude Code availability
    const claudeSpinner = ora('Checking Claude Code availability...').start();
    const claudeAvailable = await claudeBridge.checkClaudeCodeAvailability();
    if (!claudeAvailable) {
      claudeSpinner.fail('Claude Code not available');
      logger.error('❌ Claude Code CLI not found. Please install and authenticate Claude Code first.');
      logger.info('💡 Visit: https://docs.anthropic.com/claude-code for installation instructions');
      process.exit(1);
    }
    claudeSpinner.succeed('Claude Code available');

    // Initialize agent router
    spinner.text = 'Initializing agent router...';
    const agentRouter = new AgentRouter(claudeBridge);

    // Initialize MCP server manager
    spinner.text = 'Starting MCP servers...';
    const serverManager = new MCPServerManager();
    await serverManager.start();

    spinner.succeed('A2A platform initialized');

    // Route the query
    const routingSpinner = ora('Routing query to appropriate agent...').start();
    
    try {
      const routingResult = await agentRouter.routeQuery(query, options.agent);
      
      routingSpinner.succeed(
        `Query routed to ${chalk.blue(routingResult.agent)} agent (confidence: ${chalk.green(routingResult.confidence.toFixed(2))})`
      );

      if (routingResult.confidence < 0.7) {
        logger.warn(`⚠️ Low confidence routing (${routingResult.confidence.toFixed(2)}). Result may not be optimal.`);
      }

      // Log routing reasoning in debug mode
      if (process.env.A2A_DEBUG === 'true') {
        logger.debug(`Routing reasoning: ${routingResult.reasoning}`);
      }

      // Execute the query with the selected agent
      const executionSpinner = ora(`Executing query with ${routingResult.agent} agent...`).start();
      
      let result;
      try {
        if (routingResult.agent === 'falco') {
          result = await executeSecurityQuery(query, routingResult, serverManager);
        } else if (routingResult.agent === 'prometheus') {
          result = await executeMonitoringQuery(query, routingResult, serverManager);
        } else {
          result = await executeGeneralQuery(query, routingResult, claudeBridge);
        }

        executionSpinner.succeed('Query executed successfully');

        // Format and display results
        console.log('DEBUG: result object before display:', JSON.stringify(result, null, 2));
        await displayResults(result, options, query);

        // Save to file if requested
        if (options.output) {
          await saveOutput(result, options.output, options.format || 'text');
          logger.info(`💾 Results saved to ${options.output}`);
        }

        // Update routing history for optimization
        await agentRouter.optimizeRouting();

      } catch (executionError) {
        executionSpinner.fail('Query execution failed');
        throw executionError;
      }

    } catch (routingError) {
      routingSpinner.fail('Failed to route query');
      throw routingError;
    }

  } catch (error) {
    spinner.fail('Failed to initialize A2A platform');
    
    // 🎯 Claude Code 에러 특별 처리
    if (error instanceof ClaudeCodeError) {
      console.log('\n' + chalk.red('═'.repeat(60)));
      console.log(chalk.red(error.userMessage.title));
      console.log(chalk.red('═'.repeat(60)));
      
      console.log(chalk.white(`\n${error.userMessage.message}`));
      
      if (error.userMessage.details) {
        console.log(chalk.gray(`\nDetails: ${error.userMessage.details}`));
      }
      
      console.log(chalk.yellow('\n💡 How to fix this:'));
      error.userMessage.actions.forEach((action, index) => {
        console.log(chalk.cyan(`  ${index + 1}. ${action}`));
      });
      
      if (error.userMessage.retryAfter) {
        console.log(chalk.magenta(`\n⏰ You can try again after: ${error.userMessage.retryAfter}`));
      }
      
      if (process.env.A2A_DEBUG === 'true') {
        console.log(chalk.gray('\n🔍 Debug Information:'));
        console.log(chalk.gray(`   Error Type: ${error.details.errorType}`));
        console.log(chalk.gray(`   Exit Code: ${error.details.exitCode}`));
        console.log(chalk.gray(`   Recoverable: ${error.details.recoverable}`));
        console.log(chalk.gray(`   Original Error: ${error.details.originalError}`));
      }
      
      console.log(chalk.blue('\n💬 Need more help?'));
      console.log(chalk.blue('   • Visit: https://docs.anthropic.com/claude-code'));
      console.log(chalk.blue('   • Run: a2a doctor --help'));
      console.log(chalk.blue('   • Enable debug mode: A2A_DEBUG=true a2a query "..."'));
      
      const exitCode = ClaudeErrorHandler.getExitCode(error.userMessage);
      process.exit(exitCode);
    }
    
    // 기타 일반 에러 처리
    logger.error(`❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    
    // Provide helpful suggestions for non-Claude errors
    if (error instanceof Error) {
      if (error.message.includes('ECONNREFUSED')) {
        logger.info('💡 Make sure Prometheus and Falco services are running');
      } else if (error.message.includes('not found')) {
        logger.info('💡 Check that all required tools are installed and in PATH');
      } else if (error.message.includes('RBAC')) {
        logger.info('💡 Check your Kubernetes permissions and authentication');
      }
    }
    
    process.exit(1);
  }
}

async function executeSecurityQuery(
  query: string,
  routingResult: any,
  serverManager: MCPServerManager
): Promise<any> {
  const falcoServer = serverManager.getServer('falco');
  if (!falcoServer) {
    throw new Error('Falco server not available');
  }

  // Determine which security tool to use based on query content
  const queryLower = query.toLowerCase();
  
  if (queryLower.includes('threat') || queryLower.includes('detect') || queryLower.includes('attack')) {
    return await falcoServer.handleToolCall('detect_threats', {
      timeRange: extractTimeRange(query),
      severity: extractSeverity(query)
    });
  } else if (queryLower.includes('rule') || queryLower.includes('validate')) {
    return await falcoServer.handleToolCall('check_rules', {
      action: queryLower.includes('validate') ? 'validate' : 'list'
    });
  } else if (queryLower.includes('score') || queryLower.includes('audit') || queryLower.includes('posture')) {
    return await falcoServer.handleToolCall('security_score', {
      timeRange: extractTimeRange(query),
      baseline: queryLower.includes('baseline')
    });
  } else {
    // Default to threat detection
    return await falcoServer.handleToolCall('detect_threats', {
      timeRange: '1h',
      severity: 'medium'
    });
  }
}

async function executeMonitoringQuery(
  query: string,
  routingResult: any,
  serverManager: MCPServerManager
): Promise<any> {
  const prometheusServer = serverManager.getServer('prometheus');
  if (!prometheusServer) {
    throw new Error('Prometheus server not available');
  }

  const queryLower = query.toLowerCase();
  
  if (queryLower.includes('alert')) {
    return await prometheusServer.handleToolCall('get_alerts', {
      action: 'list_active',
      severity: extractSeverity(query),
      state: queryLower.includes('firing') ? 'firing' : 'all'
    });
  } else {
    // Try to extract PromQL query or use common metrics
    const promqlQuery = extractPromQLQuery(query) || inferMetricQuery(query);
    return await prometheusServer.handleToolCall('query_metrics', {
      query: promqlQuery,
      timeRange: extractTimeRange(query),
      format: queryLower.includes('history') || queryLower.includes('trend') ? 'range' : 'instant'
    });
  }
}

async function executeGeneralQuery(
  query: string,
  routingResult: any,
  claudeBridge: ClaudeCodeBridge
): Promise<any> {
  try {
    const queryLower = query.toLowerCase();
    
    // 설치 관련 쿼리 감지
    const isInstallationQuery = queryLower.includes('설치') || queryLower.includes('install') || 
                               queryLower.includes('deploy') || queryLower.includes('셋업') ||
                               queryLower.includes('setup');
    
    if (isInstallationQuery) {
      return await executeInstallationQuery(query, queryLower);
    }
    
    // Use Claude Code for general DevOps questions
    const response = await claudeBridge.executeWithAgent('general', query);
    
    if (!response.success) {
      throw new Error(response.error || 'General query execution failed');
    }

    return {
      success: true,
      data: {
        query,
        agent: 'general',
        response: response.data,
        type: 'text',
        timestamp: new Date().toISOString()
      }
    };
  } catch (error) {
    console.error('executeGeneralQuery error:', error);
    throw error;
  }
}

async function executeInstallationQuery(query: string, queryLower: string): Promise<any> {
  try {
    console.log('executeInstallationQuery started with query:', query);
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);
  
  const installationSteps: string[] = [];
  const installedComponents: string[] = [];
  const errors: string[] = [];
  const warnings: string[] = [];
  
  // 사전 요구사항 체크
  installationSteps.push('Checking prerequisites...');
  
  // Helm 설치 여부 확인
  let helmAvailable = false;
  try {
    await execAsync('helm version');
    installationSteps.push('✅ Helm is available');
    helmAvailable = true;
  } catch (error) {
    const warnMsg = '⚠️ Helm is not installed. Using kubectl-based installation instead.';
    installationSteps.push(warnMsg);
    warnings.push('Helm not available - using kubectl fallback');
    
    // Helm이 없으면 kubectl 기반 설치로 대체
    installationSteps.push('📝 Switching to kubectl-based installation...');
  }
  
  // kubectl 설치 여부 확인
  try {
    await execAsync('kubectl version --client');
    installationSteps.push('✅ kubectl is available');
  } catch (error) {
    const errorMsg = '❌ kubectl is not installed. Please install kubectl first.';
    installationSteps.push(errorMsg);
    errors.push(errorMsg);
    return createInstallationResult(query, installationSteps, installedComponents, errors, []);
  }
  
  // Falco 설치 감지
  if (queryLower.includes('falco')) {
    try {
      installationSteps.push('Installing Falco security monitoring...');
      
      // Helm 사용 가능한 경우
      if (helmAvailable) {
        // Helm repository 추가
        await execAsync('helm repo add falcosecurity https://falcosecurity.github.io/charts');
        await execAsync('helm repo update');
        installationSteps.push('✅ Added Falcosecurity Helm repository');
        
        // Falco 설치
        await execAsync('helm upgrade --install falco falcosecurity/falco --namespace falco-system --create-namespace --set tty=true');
        installationSteps.push('✅ Installed Falco via Helm');
      } else {
        // kubectl 기반 설치
        await execAsync('kubectl create namespace falco-system --dry-run=client -o yaml | kubectl apply -f -');
        installationSteps.push('✅ Created falco-system namespace');
        
        // Falco DaemonSet YAML 적용
        const falcoManifest = `
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
  namespace: falco-system
spec:
  selector:
    matchLabels:
      app: falco
  template:
    metadata:
      labels:
        app: falco
    spec:
      containers:
      - name: falco
        image: falcosecurity/falco:0.36.2
        args: ["/usr/bin/falco", "--cri", "/run/containerd/containerd.sock"]
        securityContext:
          privileged: true
        volumeMounts:
        - name: dev
          mountPath: /dev
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: boot
          mountPath: /host/boot
          readOnly: true
        - name: lib-modules
          mountPath: /host/lib/modules
          readOnly: true
        - name: usr
          mountPath: /host/usr
          readOnly: true
        - name: etc
          mountPath: /host/etc
          readOnly: true
      volumes:
      - name: dev
        hostPath:
          path: /dev
      - name: proc
        hostPath:
          path: /proc
      - name: boot
        hostPath:
          path: /boot
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: usr
        hostPath:
          path: /usr
      - name: etc
        hostPath:
          path: /etc
      hostNetwork: true
      hostPID: true
      tolerations:
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
`;
        
        const fs = await import('fs');
        const path = await import('path');
        const tempFile = path.join(__dirname, 'falco-manifest.yaml');
        await fs.promises.writeFile(tempFile, falcoManifest);
        
        await execAsync(`kubectl apply -f ${tempFile}`);
        await fs.promises.unlink(tempFile);
        installationSteps.push('✅ Installed Falco via kubectl');
      }
      
      installedComponents.push('Falco');
    } catch (error) {
      const errorMsg = `❌ Falco installation failed: ${error instanceof Error ? error.message : 'Unknown error'}`;
      installationSteps.push(errorMsg);
      errors.push(errorMsg);
    }
  }
  
  // Prometheus 설치 감지
  if (queryLower.includes('prometheus')) {
    try {
      installationSteps.push('Installing Prometheus monitoring stack...');
      
      // Helm 사용 가능한 경우
      if (helmAvailable) {
        // Prometheus Community Helm repository 추가
        await execAsync('helm repo add prometheus-community https://prometheus-community.github.io/helm-charts');
        await execAsync('helm repo update');
        installationSteps.push('✅ Added Prometheus Community Helm repository');
        
        // kube-prometheus-stack 설치 (Prometheus + Grafana + AlertManager)
        await execAsync('helm upgrade --install monitoring prometheus-community/kube-prometheus-stack --namespace monitoring --create-namespace --set prometheus.service.type=NodePort --set grafana.service.type=NodePort --set alertmanager.service.type=NodePort');
        installationSteps.push('✅ Installed Prometheus stack via Helm');
      } else {
        // kubectl 기반 간단한 Prometheus 설치
        await execAsync('kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -');
        installationSteps.push('✅ Created monitoring namespace');
        
        // 간단한 Prometheus deployment YAML
        const prometheusManifest = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      containers:
      - name: prometheus
        image: prom/prometheus:latest
        ports:
        - containerPort: 9090
        args:
          - '--config.file=/etc/prometheus/prometheus.yml'
          - '--storage.tsdb.path=/prometheus'
          - '--web.console.libraries=/etc/prometheus/console_libraries'
          - '--web.console.templates=/etc/prometheus/consoles'
          - '--web.enable-lifecycle'
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
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
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
---
apiVersion: v1
kind: Service
metadata:
  name: prometheus
  namespace: monitoring
spec:
  selector:
    app: prometheus
  ports:
    - protocol: TCP
      port: 9090
      targetPort: 9090
      nodePort: 30090
  type: NodePort
`;
        
        const fs = await import('fs');
        const path = await import('path');
        const tempFile = path.join(__dirname, 'prometheus-manifest.yaml');
        await fs.promises.writeFile(tempFile, prometheusManifest);
        
        await execAsync(`kubectl apply -f ${tempFile}`);
        await fs.promises.unlink(tempFile);
        installationSteps.push('✅ Installed basic Prometheus deployment');
        
        installationSteps.push('⚠️ Basic Prometheus installation complete. For full stack (Grafana, AlertManager), please install Helm.');
      }
      
      installedComponents.push('Prometheus');
      if (errors.filter(e => e.includes('Helm')).length === 0) {
        installedComponents.push('Grafana');
        installedComponents.push('AlertManager');
      }
    } catch (error) {
      const errorMsg = `❌ Prometheus installation failed: ${error instanceof Error ? error.message : 'Unknown error'}`;
      installationSteps.push(errorMsg);
      errors.push(errorMsg);
    }
  }
  
  // 설치 후 상태 확인
  const postInstallInfo: string[] = [];
  if (installedComponents.includes('Falco')) {
    postInstallInfo.push('🔒 Falco is monitoring for security threats');
    postInstallInfo.push('📋 Check Falco logs: kubectl logs -l app=falco -n falco-system');
  }
  if (installedComponents.includes('Prometheus')) {
    postInstallInfo.push('📊 Prometheus is collecting metrics');
    if (installedComponents.includes('Grafana')) {
      postInstallInfo.push('🎯 Access Grafana: kubectl port-forward -n monitoring svc/monitoring-grafana 3000:80');
      postInstallInfo.push('🚨 Access Prometheus: kubectl port-forward -n monitoring svc/monitoring-kube-prometheus-prometheus 9090:9090');
    }
  }
  
  console.log('executeInstallationQuery completed successfully');
  return createInstallationResult(query, installationSteps, installedComponents, errors, warnings, postInstallInfo);
  } catch (error) {
    console.error('executeInstallationQuery error:', error);
    throw error;
  }
}

function createInstallationResult(
  query: string, 
  installationSteps: string[], 
  installedComponents: string[], 
  errors: string[], 
  warnings: string[],
  postInstallInfo: string[]
): any {
  // 설치 결과 요약
  let summary = '';
  if (installedComponents.length > 0) {
    summary = `Successfully installed: ${installedComponents.join(', ')}`;
  }
  if (errors.length > 0) {
    summary += errors.length > 0 && installedComponents.length > 0 ? '\n' : '';
    summary += `Failed components: ${errors.length}`;
  }
  
  return {
    success: errors.length === 0 && installedComponents.length > 0,
    data: {
      query,
      agent: 'general',
      type: 'installation',
      timestamp: new Date().toISOString(),
      summary,
      installationSteps,
      installedComponents,
      errors,
      warnings,
      postInstallInfo,
      response: `Installation completed. ${summary}`
    }
  };
}

async function displayResults(result: any, options: QueryOptions, originalQuery: string): Promise<void> {
  const format = options.format || 'text';

  console.log(chalk.blue('\\n' + '='.repeat(60)));
  console.log(chalk.blue(`Query: ${originalQuery}`));
  console.log(chalk.blue('='.repeat(60)));

  if (!result.success) {
    console.log(chalk.red('❌ Query failed:'));
    console.log(chalk.red(result.error || 'Unknown error'));
    return;
  }

  switch (format.toLowerCase()) {
    case 'json':
      console.log(JSON.stringify(result.data, null, 2));
      break;
    
    case 'yaml':
      const yaml = await import('yaml');
      console.log(yaml.stringify(result.data));
      break;
    
    case 'table':
      displayAsTable(result.data);
      break;
    
    case 'csv':
      displayAsCSV(result.data);
      break;
    
    default: // text
      displayAsText(result.data);
      break;
  }

  console.log(chalk.blue('\\n' + '='.repeat(60)));
}

function displayAsText(data: any): void {
  // 설치 결과 표시
  if (data.type === 'installation') {
    if (data.installationSteps && data.installationSteps.length > 0) {
      console.log(chalk.blue('\\n🔧 Installation Steps:'));
      data.installationSteps.forEach((step: string) => {
        console.log(`  ${step}`);
      });
    }

    if (data.installedComponents && data.installedComponents.length > 0) {
      console.log(chalk.green('\\n✅ Successfully Installed:'));
      data.installedComponents.forEach((component: string) => {
        console.log(`  • ${component}`);
      });
    }

    if (data.errors && data.errors.length > 0) {
      console.log(chalk.red('\\n❌ Installation Errors:'));
      data.errors.forEach((error: string) => {
        console.log(`  • ${error}`);
      });
    }

    if (data.warnings && data.warnings.length > 0) {
      console.log(chalk.yellow('\\n⚠️ Warnings:'));
      data.warnings.forEach((warning: string) => {
        console.log(`  • ${warning}`);
      });
    }

    if (data.postInstallInfo && data.postInstallInfo.length > 0) {
      console.log(chalk.cyan('\\n📋 Next Steps:'));
      data.postInstallInfo.forEach((info: string) => {
        console.log(`  • ${info}`);
      });
    }

    if (data.summary) {
      console.log(chalk.yellow('\\n📊 Summary:'));
      console.log(`  ${data.summary}`);
    }
    return;
  }

  // 기존 표시 로직
  if (data.summary) {
    console.log(chalk.green('\\n📊 Summary:'));
    console.log(formatSummary(data.summary));
  }

  if (data.events && data.events.length > 0) {
    console.log(chalk.yellow('\\n🔍 Security Events:'));
    data.events.slice(0, 10).forEach((event: any, index: number) => {
      console.log(`${index + 1}. ${formatEvent(event)}`);
    });
  }

  if (data.alerts && data.alerts.length > 0) {
    console.log(chalk.red('\\n🚨 Active Alerts:'));
    data.alerts.slice(0, 10).forEach((alert: any, index: number) => {
      console.log(`${index + 1}. ${formatAlert(alert)}`);
    });
  }

  if (data.metrics && data.metrics.length > 0) {
    console.log(chalk.cyan('\\n📈 Metrics:'));
    data.metrics.slice(0, 10).forEach((metric: any, index: number) => {
      console.log(`${index + 1}. ${formatMetric(metric)}`);
    });
  }

  if (data.recommendations && data.recommendations.length > 0) {
    console.log(chalk.magenta('\\n💡 Recommendations:'));
    data.recommendations.forEach((rec: string, index: number) => {
      console.log(`${index + 1}. ${rec}`);
    });
  }

  if (data.response) {
    console.log(chalk.white('\\n📝 Response:'));
    console.log(data.response);
  }
}

function displayAsTable(data: any): void {
  // This would use a table formatting library like cli-table3
  // For now, display as formatted text
  displayAsText(data);
}

function displayAsCSV(data: any): void {
  // Convert data to CSV format
  if (data.events) {
    console.log('timestamp,severity,rule,description');
    data.events.forEach((event: any) => {
      console.log(`${event.timestamp},${event.severity},${event.rule},"${event.description}"`);
    });
  } else if (data.metrics) {
    console.log('name,value,timestamp,unit');
    data.metrics.forEach((metric: any) => {
      console.log(`${metric.name},${metric.value},${metric.timestamp},${metric.unit || ''}`);
    });
  } else {
    console.log('No tabular data available for CSV format');
  }
}

function formatSummary(summary: any): string {
  const lines = [];
  for (const [key, value] of Object.entries(summary)) {
    if (typeof value === 'object') continue;
    const formattedKey = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
    lines.push(`  ${formattedKey}: ${chalk.white(value)}`);
  }
  return lines.join('\\n');
}

function formatEvent(event: any): string {
  const severity = getSeverityColor(event.severity);
  return `${severity} ${chalk.white(event.rule)} - ${event.description} (${event.timestamp})`;
}

function formatAlert(alert: any): string {
  const severity = getSeverityColor(alert.severity);
  const state = alert.state === 'firing' ? chalk.red('FIRING') : chalk.yellow('PENDING');
  return `${severity} [${state}] ${chalk.white(alert.alertname)} - ${alert.summary}`;
}

function formatMetric(metric: any): string {
  const value = formatMetricValue(metric.value, metric.unit);
  return `${chalk.cyan(metric.name)}: ${chalk.white(value)}`;
}

function getSeverityColor(severity: string): string {
  switch (severity?.toLowerCase()) {
    case 'critical': return chalk.red('🔴 CRITICAL');
    case 'high': return chalk.red('🟠 HIGH');
    case 'medium': return chalk.yellow('🟡 MEDIUM');
    case 'low': return chalk.green('🟢 LOW');
    default: return chalk.gray('⚪ UNKNOWN');
  }
}

function formatMetricValue(value: number, unit?: string): string {
  if (unit === 'bytes') {
    return formatBytes(value);
  } else if (unit === '%') {
    return `${value.toFixed(1)}%`;
  } else if (unit === 's') {
    return formatDuration(value);
  }
  return value.toString();
}

function formatBytes(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024;
    i++;
  }
  return `${bytes.toFixed(1)} ${units[i]}`;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

async function saveOutput(result: any, outputPath: string, format: string): Promise<void> {
  const fullPath = path.resolve(outputPath);
  let content: string;

  switch (format.toLowerCase()) {
    case 'json':
      content = JSON.stringify(result, null, 2);
      break;
    case 'yaml':
      const yaml = await import('yaml');
      content = yaml.stringify(result);
      break;
    default:
      content = JSON.stringify(result, null, 2);
      break;
  }

  await writeFile(fullPath, content, 'utf8');
}

// Utility functions for query parsing
function extractTimeRange(query: string): string {
  const timeRegex = /(\\d+)\\s*(minute|min|hour|hr|h|day|d|week|w)/i;
  const match = query.match(timeRegex);
  if (match) {
    const value = match[1];
    const unit = match[2].toLowerCase();
    if (unit.startsWith('min')) return `${value}m`;
    if (unit.startsWith('h')) return `${value}h`;
    if (unit.startsWith('d')) return `${value}d`;
    if (unit.startsWith('w')) return `${value}w`;
  }
  return '1h'; // default
}

function extractSeverity(query: string): string {
  const severities = ['critical', 'high', 'medium', 'low'];
  for (const severity of severities) {
    if (query.toLowerCase().includes(severity)) {
      return severity;
    }
  }
  return 'medium'; // default
}

function extractPromQLQuery(query: string): string | null {
  // Look for PromQL patterns in the query
  const promqlPatterns = [
    /rate\\([^)]+\\[\\d+[smhdw]\\]\\)/g,
    /\\b[a-zA-Z_:][a-zA-Z0-9_:]*\\{[^}]*\\}/g,
    /\\b(sum|avg|min|max|count)\\s*\\([^)]+\\)/g
  ];

  for (const pattern of promqlPatterns) {
    const matches = query.match(pattern);
    if (matches) {
      return matches[0];
    }
  }

  return null;
}

function inferMetricQuery(query: string): string {
  const queryLower = query.toLowerCase();
  
  if (queryLower.includes('cpu')) {
    return 'rate(cpu_usage_seconds_total[5m]) * 100';
  } else if (queryLower.includes('memory')) {
    return '(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100';
  } else if (queryLower.includes('disk')) {
    return '100 - ((node_filesystem_avail_bytes * 100) / node_filesystem_size_bytes)';
  } else if (queryLower.includes('network')) {
    return 'rate(node_network_receive_bytes_total[5m])';
  } else if (queryLower.includes('up') || queryLower.includes('health')) {
    return 'up';
  }
  
  return 'up'; // fallback
}

// Helper function to get current user identity
async function getCurrentUser(): Promise<string> {
  try {
    // Try to get from environment variable first
    if (process.env.A2A_USER) {
      return process.env.A2A_USER;
    }

    // Try to get from kubectl current context user
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);
    
    try {
      const { stdout } = await execAsync('kubectl config view --minify --raw -o jsonpath="{.contexts[0].context.user}"');
      if (stdout.trim()) {
        return stdout.trim();
      }
    } catch {
      // kubectl user extraction failed
    }

    // Try to get from OS user
    if (process.env.USER || process.env.USERNAME) {
      return process.env.USER || process.env.USERNAME || 'unknown';
    }

    return 'current-user';
  } catch {
    return 'unknown-user';
  }
}