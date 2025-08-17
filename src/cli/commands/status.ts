import { ConnectionManager, EnvironmentStatus } from '@core/ConnectionManager';
import { KubernetesClient } from '@core/KubernetesClient';
import { Logger } from '../utils/logger';
import chalk from 'chalk';
import ora from 'ora';
import boxen from 'boxen';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const logger = Logger.getInstance();

export interface StatusOptions {
  detailed?: boolean;
  json?: boolean;
  watch?: boolean;
  component?: string;
}

export async function statusCommand(options: StatusOptions): Promise<void> {
  const connectionManager = new ConnectionManager();

  try {
    if (options.watch) {
      await watchStatus(connectionManager);
    } else if (options.component) {
      await showComponentStatus(connectionManager, options.component, options.detailed || false);
    } else if (options.json) {
      await showStatusJson(connectionManager);
    } else {
      await showStatusOverview(connectionManager, options.detailed || false);
    }
  } catch (error) {
    logger.error(`Status command failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    process.exit(1);
  } finally {
    await connectionManager.disconnect();
  }
}

async function showStatusOverview(connectionManager: ConnectionManager, detailed: boolean): Promise<void> {
  const spinner = ora('Checking environment status...').start();
  
  try {
    const environmentStatus = await connectionManager.checkEnvironmentStatus();
    spinner.succeed('Environment status checked');
    
    // Overall status header
    displayOverallStatus(environmentStatus);
    
    // Component status
    displayComponentStatus(environmentStatus, detailed);
    
    // Cluster information if Kubernetes is connected
    const k8sConnection = environmentStatus.connections.find(c => c.component === 'kubernetes');
    if (k8sConnection?.status === 'connected' && detailed) {
      await displayClusterDetails(environmentStatus);
    }
    
    // Blockers and recommendations
    displayBlockersAndRecommendations(environmentStatus);
    
    // Quick actions
    displayQuickActions(environmentStatus);
    
  } catch (error) {
    spinner.fail('Failed to check status');
    throw error;
  }
}

function displayOverallStatus(environmentStatus: EnvironmentStatus): void {
  const statusEmoji = environmentStatus.overall === 'ready' ? '🟢' : 
                     environmentStatus.overall === 'partial' ? '🟡' : '🔴';
  
  const statusColor = environmentStatus.overall === 'ready' ? chalk.green : 
                     environmentStatus.overall === 'partial' ? chalk.yellow : chalk.red;
  
  const statusText = environmentStatus.overall === 'ready' ? 'READY' : 
                    environmentStatus.overall === 'partial' ? 'PARTIAL' : 'NOT READY';
  
  const overallBox = boxen(
    `${statusEmoji} A2A Platform Status: ${statusColor.bold(statusText)}\\n\\n` +
    `Platform is ${environmentStatus.overall === 'ready' ? 'fully operational' : 
                    environmentStatus.overall === 'partial' ? 'partially functional' : 'not ready for use'}`,
    {
      padding: 1,
      margin: 1,
      borderStyle: 'round',
      borderColor: environmentStatus.overall === 'ready' ? 'green' : 
                   environmentStatus.overall === 'partial' ? 'yellow' : 'red'
    }
  );
  
  console.log(overallBox);
}

function displayComponentStatus(environmentStatus: EnvironmentStatus, detailed: boolean): void {
  console.log(chalk.blue('🔧 Component Status'));
  console.log(chalk.blue('=' .repeat(50)));
  
  for (const connection of environmentStatus.connections) {
    const statusIcon = getStatusIcon(connection.status);
    const statusColor = getStatusColor(connection.status);
    
    console.log(`${statusIcon} ${chalk.bold(connection.component.toUpperCase())}: ${statusColor(connection.status.toUpperCase())}`);
    
    // Show key details
    if (connection.details.version) {
      console.log(`   Version: ${chalk.gray(connection.details.version)}`);
    }
    
    if (connection.details.endpoint) {
      console.log(`   Endpoint: ${chalk.gray(connection.details.endpoint)}`);
    }
    
    if (connection.details.cluster) {
      console.log(`   Cluster: ${chalk.cyan(connection.details.cluster)}`);
    }
    
    if (connection.details.namespace) {
      console.log(`   Namespace: ${chalk.cyan(connection.details.namespace)}`);
    }
    
    // Show error if any
    if (connection.details.error) {
      console.log(`   Error: ${chalk.red(connection.details.error)}`);
    }
    
    // Show limitations if any
    if (connection.details.limitations && connection.details.limitations.length > 0) {
      console.log(`   Limitations: ${chalk.yellow(connection.details.limitations.join(', '))}`);
    }
    
    // Show detailed info if requested
    if (detailed) {
      console.log(`   Last Check: ${chalk.gray(new Date(connection.details.lastCheck).toLocaleString())}`);
    }
    
    console.log('');
  }
}

async function displayClusterDetails(environmentStatus: EnvironmentStatus): Promise<void> {
  console.log(chalk.blue('🌐 Cluster Details'));
  console.log(chalk.blue('=' .repeat(50)));
  
  const kubernetesClient = new KubernetesClient();
  
  try {
    await kubernetesClient.connect();
    const healthCheck = await kubernetesClient.healthCheck();
    
    if (environmentStatus.cluster) {
      const cluster = environmentStatus.cluster;
      
      console.log(`📍 Name: ${chalk.cyan(cluster.name)}`);
      console.log(`🔗 Server: ${chalk.gray(cluster.server)}`);
      console.log(`🏷️  Version: ${chalk.gray(cluster.version)}`);
      console.log(`🖥️  Nodes: ${chalk.green(cluster.nodeCount)} (${healthCheck.details.readyNodes} ready)`);
      console.log(`📂 Namespaces: ${chalk.cyan(cluster.namespaces.length)}`);
      console.log(`🔐 RBAC: ${cluster.rbacEnabled ? chalk.green('Enabled') : chalk.red('Disabled')}`);
      console.log(`⚡ Response Time: ${chalk.gray(healthCheck.details.responseTime + 'ms')}`);
      
      // Show namespace list
      console.log('\\n📋 Available Namespaces:');
      const currentNamespace = environmentStatus.connections.find(c => c.component === 'kubernetes')?.details.namespace;
      
      cluster.namespaces.slice(0, 10).forEach(ns => {
        const marker = ns === currentNamespace ? chalk.green('* ') : '  ';
        console.log(`${marker}${ns}`);
      });
      
      if (cluster.namespaces.length > 10) {
        console.log(chalk.gray(`  ... and ${cluster.namespaces.length - 10} more`));
      }
      
      // Show resource counts
      try {
        console.log('\\n📦 Resource Summary:');
        
        const { stdout: podsCount } = await execAsync('kubectl get pods --all-namespaces --no-headers 2>/dev/null | wc -l');
        const { stdout: servicesCount } = await execAsync('kubectl get services --all-namespaces --no-headers 2>/dev/null | wc -l');
        const { stdout: deploymentsCount } = await execAsync('kubectl get deployments --all-namespaces --no-headers 2>/dev/null | wc -l');
        
        console.log(`  Pods: ${chalk.green(podsCount.trim())}`);
        console.log(`  Services: ${chalk.green(servicesCount.trim())}`);
        console.log(`  Deployments: ${chalk.green(deploymentsCount.trim())}`);
      } catch {
        console.log('  Resource counts: ' + chalk.yellow('Unable to fetch'));
      }
    }
    
  } catch (error) {
    console.log(chalk.yellow('Unable to fetch detailed cluster information'));
    console.log(chalk.gray(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
  }
  
  console.log('');
}

function displayBlockersAndRecommendations(environmentStatus: EnvironmentStatus): void {
  // Show blockers
  if (environmentStatus.blockers.length > 0) {
    console.log(chalk.red('🚫 Blockers (Must Fix):'));
    environmentStatus.blockers.forEach(blocker => {
      console.log(chalk.red(`   • ${blocker}`));
    });
    console.log('');
  }
  
  // Show recommendations
  if (environmentStatus.recommendations.length > 0) {
    console.log(chalk.yellow('💡 Recommendations:'));
    environmentStatus.recommendations.forEach(rec => {
      console.log(chalk.yellow(`   • ${rec}`));
    });
    console.log('');
  }
}

function displayQuickActions(environmentStatus: EnvironmentStatus): void {
  console.log(chalk.blue('🔧 Quick Actions'));
  console.log(chalk.blue('=' .repeat(30)));
  
  const missingComponents = environmentStatus.connections
    .filter(c => c.status === 'unavailable' || c.status === 'not_configured')
    .map(c => c.component);
  
  if (missingComponents.length === 0) {
    console.log(chalk.green('✅ All systems operational!'));
    console.log(chalk.gray('   a2a query "your question"     Start querying'));
    console.log(chalk.gray('   a2a cluster --list           Manage clusters'));
  } else {
    console.log(chalk.gray('   a2a doctor                   Run health check'));
    console.log(chalk.gray('   a2a setup --guide            Setup missing components'));
    console.log(chalk.gray('   a2a setup --auto             Auto-setup components'));
    
    if (missingComponents.includes('kubernetes')) {
      console.log(chalk.gray('   a2a cluster --list           Check Kubernetes contexts'));
    }
  }
  
  console.log(chalk.gray('   a2a status --detailed        Show detailed status'));
  console.log(chalk.gray('   a2a status --watch           Monitor status continuously'));
}

async function showComponentStatus(connectionManager: ConnectionManager, component: string, detailed: boolean): Promise<void> {
  const spinner = ora(`Checking ${component} status...`).start();
  
  try {
    const environmentStatus = await connectionManager.checkEnvironmentStatus();
    const connection = environmentStatus.connections.find(c => c.component === component);
    
    spinner.succeed(`${component} status checked`);
    
    if (!connection) {
      console.log(chalk.red(`❌ Component '${component}' not found`));
      console.log(chalk.gray('Available components: kubernetes, falco, prometheus, alertmanager'));
      return;
    }
    
    // Component header
    const statusIcon = getStatusIcon(connection.status);
    const statusColor = getStatusColor(connection.status);
    
    const componentBox = boxen(
      `${statusIcon} ${chalk.bold(component.toUpperCase())}\\n` +
      `Status: ${statusColor(connection.status.toUpperCase())}`,
      {
        padding: 1,
        margin: 1,
        borderStyle: 'round',
        borderColor: connection.status === 'connected' ? 'green' : 
                    connection.status === 'degraded' ? 'yellow' : 'red'
      }
    );
    
    console.log(componentBox);
    
    // Detailed information
    console.log(chalk.blue('📊 Details:'));
    
    Object.entries(connection.details).forEach(([key, value]) => {
      if (key === 'limitations' && Array.isArray(value)) {
        console.log(`  ${formatKey(key)}: ${chalk.yellow(value.join(', '))}`);
      } else if (key === 'error') {
        console.log(`  ${formatKey(key)}: ${chalk.red(value)}`);
      } else if (typeof value === 'string') {
        console.log(`  ${formatKey(key)}: ${chalk.gray(value)}`);
      }
    });
    
    // Component-specific details
    if (component === 'kubernetes' && connection.status === 'connected') {
      await showKubernetesDetails();
    } else if (component === 'falco' && connection.status === 'connected') {
      await showFalcoDetails();
    } else if (component === 'prometheus' && connection.status === 'connected') {
      await showPrometheusDetails();
    }
    
    // Show troubleshooting if not connected
    if (connection.status !== 'connected') {
      showTroubleshooting(component);
    }
    
  } catch (error) {
    spinner.fail(`Failed to check ${component} status`);
    throw error;
  }
}

async function showKubernetesDetails(): Promise<void> {
  console.log('\\n' + chalk.blue('🌐 Kubernetes Details:'));
  
  try {
    // Show contexts
    const { stdout: contextsOutput } = await execAsync('kubectl config get-contexts --no-headers 2>/dev/null');
    const contexts = contextsOutput.trim().split('\\n').filter(line => line.length > 0);
    
    console.log(`  Available Contexts: ${chalk.cyan(contexts.length)}`);
    
    // Show current pods in current namespace
    const { stdout: podsOutput } = await execAsync('kubectl get pods --no-headers 2>/dev/null');
    const pods = podsOutput.trim().split('\\n').filter(line => line.length > 0);
    
    if (pods.length > 0 && pods[0] !== '') {
      console.log(`  Pods in Current Namespace: ${chalk.green(pods.length)}`);
      
      // Show pod status summary
      const runningPods = pods.filter(pod => pod.includes('Running')).length;
      const pendingPods = pods.filter(pod => pod.includes('Pending')).length;
      const errorPods = pods.filter(pod => pod.includes('Error') || pod.includes('CrashLoopBackOff')).length;
      
      console.log(`    Running: ${chalk.green(runningPods)}`);
      if (pendingPods > 0) console.log(`    Pending: ${chalk.yellow(pendingPods)}`);
      if (errorPods > 0) console.log(`    Error: ${chalk.red(errorPods)}`);
    }
    
  } catch (error) {
    console.log(`  ${chalk.yellow('Unable to fetch Kubernetes details')}`);
  }
}

async function showFalcoDetails(): Promise<void> {
  console.log('\\n' + chalk.blue('🛡️ Falco Details:'));
  
  try {
    // Check if running as service
    try {
      await execAsync('systemctl is-active falco 2>/dev/null');
      console.log(`  Service Status: ${chalk.green('Active')}`);
    } catch {
      console.log(`  Service Status: ${chalk.yellow('Not running as service')}`);
    }
    
    // Check log accessibility
    const logPaths = ['/var/log/falco.log', '/var/log/syslog'];
    for (const logPath of logPaths) {
      try {
        await execAsync(`test -r ${logPath}`);
        console.log(`  Log Access: ${chalk.green(logPath)}`);
        
        // Show recent event count
        const { stdout: eventCount } = await execAsync(`grep -c "falco" ${logPath} 2>/dev/null | tail -1 || echo "0"`);
        console.log(`  Recent Events: ${chalk.cyan(eventCount.trim())}`);
        break;
      } catch {
        continue;
      }
    }
    
  } catch (error) {
    console.log(`  ${chalk.yellow('Unable to fetch Falco details')}`);
  }
}

async function showPrometheusDetails(): Promise<void> {
  console.log('\\n' + chalk.blue('📊 Prometheus Details:'));
  
  try {
    const axios = await import('axios');
    
    // Get target count
    const targetsResponse = await axios.default.get('http://localhost:9090/api/v1/targets', { timeout: 5000 });
    const activeTargets = targetsResponse.data.data.activeTargets.length;
    const upTargets = targetsResponse.data.data.activeTargets.filter((t: any) => t.health === 'up').length;
    
    console.log(`  Active Targets: ${chalk.green(upTargets)}/${activeTargets}`);
    
    // Get series count
    try {
      const seriesResponse = await axios.default.get('http://localhost:9090/api/v1/query', {
        params: { query: 'prometheus_tsdb_symbol_table_size_bytes' },
        timeout: 5000
      });
      
      if (seriesResponse.data.data.result.length > 0) {
        console.log(`  Time Series: ${chalk.cyan('Active')}`);
      }
    } catch {
      // Series query failed
    }
    
    // Get storage info
    try {
      const storageResponse = await axios.default.get('http://localhost:9090/api/v1/query', {
        params: { query: 'prometheus_tsdb_lowest_timestamp' },
        timeout: 5000
      });
      
      if (storageResponse.data.data.result.length > 0) {
        console.log(`  Data Retention: ${chalk.cyan('Configured')}`);
      }
    } catch {
      // Storage query failed
    }
    
  } catch (error) {
    console.log(`  ${chalk.yellow('Unable to fetch Prometheus details')}`);
  }
}

function showTroubleshooting(component: string): void {
  console.log('\\n' + chalk.yellow('🔧 Troubleshooting:'));
  
  switch (component) {
    case 'kubernetes':
      console.log(chalk.gray('  • Check if kubectl is installed: kubectl version --client'));
      console.log(chalk.gray('  • Verify kubeconfig: kubectl config view'));
      console.log(chalk.gray('  • Test connectivity: kubectl cluster-info'));
      console.log(chalk.gray('  • Switch context: a2a cluster --switch <context>'));
      break;
      
    case 'falco':
      console.log(chalk.gray('  • Install Falco: curl -s https://falco.org/script/install | bash'));
      console.log(chalk.gray('  • Start service: sudo systemctl start falco'));
      console.log(chalk.gray('  • Check logs: sudo journalctl -u falco'));
      break;
      
    case 'prometheus':
      console.log(chalk.gray('  • Download: https://prometheus.io/download/'));
      console.log(chalk.gray('  • Start server: ./prometheus --config.file=prometheus.yml'));
      console.log(chalk.gray('  • Check web UI: http://localhost:9090'));
      break;
      
    case 'alertmanager':
      console.log(chalk.gray('  • Download: https://prometheus.io/download/'));
      console.log(chalk.gray('  • Start server: ./alertmanager --config.file=alertmanager.yml'));
      console.log(chalk.gray('  • Check web UI: http://localhost:9093'));
      break;
  }
  
  console.log(chalk.gray('  • Run setup: a2a setup --component ' + component));
}

async function showStatusJson(connectionManager: ConnectionManager): Promise<void> {
  try {
    const environmentStatus = await connectionManager.checkEnvironmentStatus();
    console.log(JSON.stringify(environmentStatus, null, 2));
  } catch (error) {
    console.log(JSON.stringify({ error: error instanceof Error ? error.message : 'Unknown error' }, null, 2));
  }
}

async function watchStatus(connectionManager: ConnectionManager): Promise<void> {
  console.log(chalk.blue('👀 Watching environment status... (Press Ctrl+C to stop)\\n'));
  
  let previousStatus: string | null = null;
  
  const checkStatus = async () => {
    try {
      const environmentStatus = await connectionManager.checkEnvironmentStatus(true); // Force check
      const statusHash = JSON.stringify(environmentStatus.connections.map(c => ({ 
        component: c.component, 
        status: c.status 
      })));
      
      if (statusHash !== previousStatus) {
        console.clear();
        console.log(chalk.blue(`🕐 Status Update: ${new Date().toLocaleTimeString()}\\n`));
        
        displayComponentStatus(environmentStatus, false);
        
        if (environmentStatus.blockers.length > 0) {
          displayBlockersAndRecommendations(environmentStatus);
        }
        
        previousStatus = statusHash;
        console.log(chalk.gray('\\nWatching for changes... (Press Ctrl+C to stop)'));
      }
    } catch (error) {
      console.log(chalk.red(`Error checking status: ${error instanceof Error ? error.message : 'Unknown error'}`));
    }
  };
  
  // Initial check
  await checkStatus();
  
  // Setup interval
  const interval = setInterval(checkStatus, 10000); // Check every 10 seconds
  
  // Handle Ctrl+C
  process.on('SIGINT', () => {
    clearInterval(interval);
    console.log(chalk.gray('\\n\\nStatus watching stopped.'));
    process.exit(0);
  });
}

function getStatusIcon(status: string): string {
  switch (status) {
    case 'connected': return '✅';
    case 'degraded': return '⚠️';
    case 'not_configured': return '⚙️';
    case 'unavailable': return '❌';
    default: return '❓';
  }
}

function getStatusColor(status: string): typeof chalk.green {
  switch (status) {
    case 'connected': return chalk.green;
    case 'degraded': return chalk.yellow;
    case 'not_configured': return chalk.blue;
    case 'unavailable': return chalk.red;
    default: return chalk.gray;
  }
}

function formatKey(key: string): string {
  return key.replace(/([A-Z])/g, ' $1')
    .replace(/^./, str => str.toUpperCase())
    .replace('_', ' ');
}