import { KubernetesClient } from '@core/KubernetesClient';
import { ConnectionManager } from '@core/ConnectionManager';
import { Logger } from '../utils/logger';
import chalk from 'chalk';
import ora from 'ora';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const logger = Logger.getInstance();

export interface ClusterOptions {
  switch?: string;
  list?: boolean;
  info?: boolean;
  namespace?: string;
}

export async function clusterCommand(options: ClusterOptions): Promise<void> {
  const connectionManager = new ConnectionManager();
  const kubernetesClient = new KubernetesClient();

  try {
    if (options.list) {
      await listClusters();
    } else if (options.switch) {
      await switchContext(options.switch);
    } else if (options.info) {
      await showClusterInfo(connectionManager, kubernetesClient);
    } else if (options.namespace) {
      await switchNamespace(options.namespace);
    } else {
      await showCurrentCluster(connectionManager, kubernetesClient);
    }
  } catch (error) {
    logger.error(`Cluster command failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    process.exit(1);
  } finally {
    await connectionManager.disconnect();
  }
}

async function listClusters(): Promise<void> {
  console.log(chalk.blue('🌐 Available Kubernetes Contexts'));
  console.log(chalk.blue('=' .repeat(50)));

  try {
    // Get all contexts
    const { stdout: contextsOutput } = await execAsync('kubectl config get-contexts -o name 2>/dev/null');
    const contexts = contextsOutput.trim().split('\\n').filter(ctx => ctx.length > 0);

    if (contexts.length === 0) {
      console.log(chalk.yellow('No Kubernetes contexts found'));
      console.log(chalk.gray('\\nTo add a cluster:'));
      console.log(chalk.gray('  • AWS EKS: aws eks update-kubeconfig --name <cluster-name>'));
      console.log(chalk.gray('  • Google GKE: gcloud container clusters get-credentials <cluster-name>'));
      console.log(chalk.gray('  • Azure AKS: az aks get-credentials --name <cluster-name> --resource-group <rg>'));
      return;
    }

    // Get current context
    let currentContext = '';
    try {
      const { stdout: currentOutput } = await execAsync('kubectl config current-context 2>/dev/null');
      currentContext = currentOutput.trim();
    } catch {
      // No current context
    }

    // Display contexts with status
    for (const context of contexts) {
      const isCurrent = context === currentContext;
      const prefix = isCurrent ? chalk.green('* ') : '  ';
      
      console.log(`${prefix}${chalk.cyan(context)}`);
      
      if (isCurrent) {
        // Show additional info for current context
        try {
          const { stdout: clusterInfo } = await execAsync(`kubectl config view --minify --output jsonpath='{.clusters[0].cluster.server}' 2>/dev/null`);
          const { stdout: namespaceInfo } = await execAsync(`kubectl config view --minify --output jsonpath='{.contexts[0].context.namespace}' 2>/dev/null`);
          
          console.log(`    Server: ${chalk.gray(clusterInfo.trim())}`);
          console.log(`    Namespace: ${chalk.gray(namespaceInfo.trim() || 'default')}`);
          
          // Check connectivity
          try {
            await execAsync('kubectl cluster-info --request-timeout=5s >/dev/null 2>&1');
            console.log(`    Status: ${chalk.green('Connected')}`);
          } catch {
            console.log(`    Status: ${chalk.red('Not accessible')}`);
          }
        } catch {
          console.log(`    Status: ${chalk.yellow('Unknown')}`);
        }
      }
    }

    console.log('\\n' + chalk.blue('Commands:'));
    console.log(chalk.gray('  a2a cluster --switch <context>   Switch to a different context'));
    console.log(chalk.gray('  a2a cluster --info              Show detailed cluster information'));

  } catch (error) {
    console.log(chalk.red('❌ Failed to list contexts'));
    console.log(chalk.gray('Make sure kubectl is installed and configured'));
  }
}

async function switchContext(targetContext: string): Promise<void> {
  const spinner = ora(`Switching to context: ${targetContext}`).start();

  try {
    // Check if context exists
    const { stdout: contextsOutput } = await execAsync('kubectl config get-contexts -o name 2>/dev/null');
    const contexts = contextsOutput.trim().split('\\n').filter(ctx => ctx.length > 0);
    
    if (!contexts.includes(targetContext)) {
      spinner.fail(`Context '${targetContext}' not found`);
      console.log(chalk.yellow('\\nAvailable contexts:'));
      contexts.forEach(ctx => console.log(chalk.gray(`  • ${ctx}`)));
      return;
    }

    // Switch context
    await execAsync(`kubectl config use-context ${targetContext}`);
    
    // Test connectivity
    spinner.text = 'Testing cluster connectivity...';
    try {
      const { stdout: clusterInfo } = await execAsync('kubectl cluster-info --request-timeout=10s 2>/dev/null');
      
      if (clusterInfo.includes('running at')) {
        spinner.succeed(`Successfully switched to ${chalk.cyan(targetContext)}`);
        
        // Show cluster info
        const { stdout: serverInfo } = await execAsync(`kubectl config view --minify --output jsonpath='{.clusters[0].cluster.server}' 2>/dev/null`);
        const { stdout: namespaceInfo } = await execAsync(`kubectl config view --minify --output jsonpath='{.contexts[0].context.namespace}' 2>/dev/null`);
        
        console.log(chalk.blue('\\n📊 Cluster Information:'));
        console.log(`  Context: ${chalk.cyan(targetContext)}`);
        console.log(`  Server: ${chalk.gray(serverInfo.trim())}`);
        console.log(`  Namespace: ${chalk.gray(namespaceInfo.trim() || 'default')}`);
        
        // Show node count
        try {
          const { stdout: nodeCount } = await execAsync('kubectl get nodes --no-headers 2>/dev/null | wc -l');
          console.log(`  Nodes: ${chalk.green(nodeCount.trim())}`);
        } catch {
          console.log(`  Nodes: ${chalk.yellow('Unknown')}`);
        }
        
      } else {
        spinner.warn(`Switched to ${chalk.cyan(targetContext)} but cluster not accessible`);
      }
      
    } catch (error) {
      spinner.warn(`Switched to ${chalk.cyan(targetContext)} but connectivity test failed`);
      console.log(chalk.yellow(`\\n⚠️ Warning: Cluster may not be accessible`));
      console.log(chalk.gray(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
    }

  } catch (error) {
    spinner.fail(`Failed to switch context`);
    console.log(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
  }
}

async function switchNamespace(targetNamespace: string): Promise<void> {
  const spinner = ora(`Switching to namespace: ${targetNamespace}`).start();

  try {
    // Check if namespace exists
    const { stdout: namespacesOutput } = await execAsync('kubectl get namespaces -o name 2>/dev/null');
    const namespaces = namespacesOutput.trim().split('\\n')
      .map(ns => ns.replace('namespace/', ''))
      .filter(ns => ns.length > 0);
    
    if (!namespaces.includes(targetNamespace)) {
      spinner.fail(`Namespace '${targetNamespace}' not found`);
      console.log(chalk.yellow('\\nAvailable namespaces:'));
      namespaces.forEach(ns => console.log(chalk.gray(`  • ${ns}`)));
      return;
    }

    // Set namespace in current context
    await execAsync(`kubectl config set-context --current --namespace=${targetNamespace}`);
    
    spinner.succeed(`Successfully switched to namespace ${chalk.cyan(targetNamespace)}`);
    
    // Show current context info
    const { stdout: currentContext } = await execAsync('kubectl config current-context 2>/dev/null');
    console.log(chalk.blue('\\n📊 Current Configuration:'));
    console.log(`  Context: ${chalk.cyan(currentContext.trim())}`);
    console.log(`  Namespace: ${chalk.cyan(targetNamespace)}`);

  } catch (error) {
    spinner.fail(`Failed to switch namespace`);
    console.log(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
  }
}

async function showCurrentCluster(connectionManager: ConnectionManager, kubernetesClient: KubernetesClient): Promise<void> {
  console.log(chalk.blue('🎯 Current Kubernetes Configuration'));
  console.log(chalk.blue('=' .repeat(50)));

  const spinner = ora('Checking cluster status...').start();

  try {
    const environmentStatus = await connectionManager.checkEnvironmentStatus();
    const k8sConnection = environmentStatus.connections.find(c => c.component === 'kubernetes');

    spinner.stop();

    if (!k8sConnection || k8sConnection.status === 'not_configured') {
      console.log(chalk.yellow('No Kubernetes configuration found'));
      console.log(chalk.gray('\\nTo get started:'));
      console.log(chalk.gray('  1. Install kubectl'));
      console.log(chalk.gray('  2. Configure cluster access (kubeconfig)'));
      console.log(chalk.gray('  3. Run: a2a cluster --list'));
      return;
    }

    if (k8sConnection.status === 'unavailable') {
      console.log(chalk.red('❌ Kubernetes cluster not accessible'));
      console.log(chalk.gray(`Error: ${k8sConnection.details.error}`));
      return;
    }

    // Show current configuration
    const statusIcon = k8sConnection.status === 'connected' ? '✅' : '⚠️';
    const statusColor = k8sConnection.status === 'connected' ? chalk.green : chalk.yellow;
    
    console.log(`${statusIcon} Status: ${statusColor(k8sConnection.status.toUpperCase())}`);
    console.log(`📍 Context: ${chalk.cyan(k8sConnection.details.cluster || 'Unknown')}`);
    console.log(`📂 Namespace: ${chalk.cyan(k8sConnection.details.namespace || 'default')}`);
    
    if (k8sConnection.details.version) {
      console.log(`🏷️  Version: ${chalk.gray(k8sConnection.details.version)}`);
    }

    // Show cluster details if connected
    if (k8sConnection.status === 'connected') {
      try {
        await kubernetesClient.connect();
        const healthCheck = await kubernetesClient.healthCheck();
        
        console.log('\\n' + chalk.blue('📊 Cluster Details:'));
        console.log(`  Response Time: ${chalk.gray(healthCheck.details.responseTime + 'ms')}`);
        console.log(`  Total Nodes: ${chalk.green(healthCheck.details.totalNodes)}`);
        console.log(`  Ready Nodes: ${chalk.green(healthCheck.details.readyNodes)}`);
        
        // Show available namespaces
        try {
          const { stdout: namespacesOutput } = await execAsync('kubectl get namespaces --no-headers -o custom-columns=":metadata.name" 2>/dev/null');
          const namespaces = namespacesOutput.trim().split('\\n').filter(ns => ns.length > 0);
          console.log(`  Namespaces: ${chalk.gray(namespaces.length)} (${namespaces.slice(0, 3).join(', ')}${namespaces.length > 3 ? '...' : ''})`);
        } catch {
          console.log(`  Namespaces: ${chalk.yellow('Unable to fetch')}`);
        }

        // Show permissions
        console.log('\\n' + chalk.blue('🔐 Permissions:'));
        const permissions = await kubernetesClient.checkPermissions();
        const permissionEntries = Object.entries(permissions).slice(0, 5);
        
        for (const [action, allowed] of permissionEntries) {
          const icon = allowed ? '✅' : '❌';
          const color = allowed ? chalk.green : chalk.red;
          console.log(`  ${icon} ${action}: ${color(allowed ? 'Allowed' : 'Denied')}`);
        }

      } catch (error) {
        console.log(chalk.yellow('\\n⚠️ Could not fetch detailed cluster information'));
        console.log(chalk.gray(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
      }
    }

    // Show limitations if any
    if (k8sConnection.details.limitations && k8sConnection.details.limitations.length > 0) {
      console.log('\\n' + chalk.yellow('⚠️ Limitations:'));
      k8sConnection.details.limitations.forEach(limitation => {
        console.log(chalk.yellow(`  • ${limitation}`));
      });
    }

    // Show quick actions
    console.log('\\n' + chalk.blue('🔧 Quick Actions:'));
    console.log(chalk.gray('  a2a cluster --list              List all available contexts'));
    console.log(chalk.gray('  a2a cluster --namespace <name>  Switch namespace'));
    console.log(chalk.gray('  a2a cluster --info              Show detailed information'));

  } catch (error) {
    spinner.fail('Failed to check cluster status');
    console.log(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
  }
}

async function showClusterInfo(connectionManager: ConnectionManager, kubernetesClient: KubernetesClient): Promise<void> {
  console.log(chalk.blue('📊 Detailed Cluster Information'));
  console.log(chalk.blue('=' .repeat(50)));

  const spinner = ora('Gathering cluster information...').start();

  try {
    const environmentStatus = await connectionManager.checkEnvironmentStatus();
    const k8sConnection = environmentStatus.connections.find(c => c.component === 'kubernetes');

    if (!k8sConnection || k8sConnection.status !== 'connected') {
      spinner.fail('Cluster not connected');
      console.log(chalk.red('❌ Cannot gather information - cluster not accessible'));
      return;
    }

    await kubernetesClient.connect();
    const healthCheck = await kubernetesClient.healthCheck();
    
    spinner.succeed('Information gathered');

    // Cluster Overview
    console.log(chalk.blue('\\n🌐 Cluster Overview:'));
    console.log(`  Context: ${chalk.cyan(k8sConnection.details.cluster)}`);
    console.log(`  Server: ${chalk.gray(healthCheck.details.server)}`);
    console.log(`  Namespace: ${chalk.cyan(k8sConnection.details.namespace)}`);
    console.log(`  Version: ${chalk.gray(k8sConnection.details.version)}`);
    console.log(`  Health: ${chalk.green(healthCheck.status.toUpperCase())}`);

    // Node Information
    console.log(chalk.blue('\\n🖥️ Node Information:'));
    console.log(`  Total Nodes: ${chalk.green(healthCheck.details.totalNodes)}`);
    console.log(`  Ready Nodes: ${chalk.green(healthCheck.details.readyNodes)}`);
    console.log(`  Response Time: ${chalk.gray(healthCheck.details.responseTime + 'ms')}`);

    // Namespaces
    try {
      const { stdout: namespacesOutput } = await execAsync('kubectl get namespaces --no-headers -o custom-columns=":metadata.name" 2>/dev/null');
      const namespaces = namespacesOutput.trim().split('\\n').filter(ns => ns.length > 0);
      
      console.log(chalk.blue('\\n📂 Namespaces:'));
      console.log(`  Total: ${chalk.green(namespaces.length)}`);
      
      // Show first 10 namespaces
      const displayNamespaces = namespaces.slice(0, 10);
      displayNamespaces.forEach(ns => {
        const isCurrent = ns === k8sConnection.details.namespace;
        const marker = isCurrent ? chalk.green('* ') : '  ';
        console.log(`${marker}${ns}`);
      });
      
      if (namespaces.length > 10) {
        console.log(chalk.gray(`  ... and ${namespaces.length - 10} more`));
      }
    } catch {
      console.log(chalk.blue('\\n📂 Namespaces: ') + chalk.yellow('Unable to fetch'));
    }

    // Resource Summary
    try {
      console.log(chalk.blue('\\n📦 Resource Summary:'));
      
      const { stdout: podsOutput } = await execAsync(`kubectl get pods --all-namespaces --no-headers 2>/dev/null | wc -l`);
      const { stdout: servicesOutput } = await execAsync(`kubectl get services --all-namespaces --no-headers 2>/dev/null | wc -l`);
      const { stdout: deploymentsOutput } = await execAsync(`kubectl get deployments --all-namespaces --no-headers 2>/dev/null | wc -l`);
      
      console.log(`  Pods: ${chalk.green(podsOutput.trim())}`);
      console.log(`  Services: ${chalk.green(servicesOutput.trim())}`);
      console.log(`  Deployments: ${chalk.green(deploymentsOutput.trim())}`);
    } catch {
      console.log(chalk.blue('\\n📦 Resource Summary: ') + chalk.yellow('Unable to fetch'));
    }

    // Permissions Summary
    console.log(chalk.blue('\\n🔐 Permission Summary:'));
    const permissions = await kubernetesClient.checkPermissions();
    
    const allowedCount = Object.values(permissions).filter(Boolean).length;
    const totalCount = Object.keys(permissions).length;
    
    console.log(`  Allowed Actions: ${chalk.green(allowedCount)}/${totalCount}`);
    
    const deniedActions = Object.entries(permissions)
      .filter(([, allowed]) => !allowed)
      .map(([action]) => action);
    
    if (deniedActions.length > 0) {
      console.log(chalk.yellow('\\n⚠️ Denied Actions:'));
      deniedActions.forEach(action => {
        console.log(chalk.red(`  • ${action}`));
      });
    }

    // Platform Detection
    try {
      const { stdout: nodeLabels } = await execAsync('kubectl get nodes -o jsonpath="{.items[0].metadata.labels}" 2>/dev/null');
      
      let platform = 'Unknown';
      if (nodeLabels.includes('eks.amazonaws.com')) {
        platform = 'Amazon EKS';
      } else if (nodeLabels.includes('gke.io')) {
        platform = 'Google GKE';
      } else if (nodeLabels.includes('kubernetes.azure.com')) {
        platform = 'Azure AKS';
      } else if (nodeLabels.includes('k3s.io')) {
        platform = 'K3s';
      } else if (nodeLabels.includes('minikube')) {
        platform = 'Minikube';
      }
      
      console.log(chalk.blue('\\n🏷️ Platform: ') + chalk.cyan(platform));
    } catch {
      // Platform detection failed
    }

  } catch (error) {
    spinner.fail('Failed to gather information');
    console.log(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
  }
}