import { ConnectionManager } from '@core/ConnectionManager';
import { Logger } from '../utils/logger';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import { exec } from 'child_process';
import { promisify } from 'util';
import { writeFile, readFile } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';

const execAsync = promisify(exec);
const logger = Logger.getInstance();

export interface SetupOptions {
  platform?: string;
  guide?: boolean;
  auto?: boolean;
  component?: string;
}

interface SetupGuide {
  platform: string;
  description: string;
  prerequisites: string[];
  steps: SetupStep[];
}

interface SetupStep {
  name: string;
  description: string;
  commands: string[];
  validation: () => Promise<boolean>;
  autoExecute?: boolean;
}

export async function setupCommand(options: SetupOptions): Promise<void> {
  console.log(chalk.blue('🔧 A2A Platform Setup Wizard'));
  console.log(chalk.blue('=' .repeat(50)));

  const connectionManager = new ConnectionManager();

  try {
    if (options.guide) {
      await showSetupGuide(connectionManager);
    } else if (options.platform) {
      await setupPlatform(options.platform, options.auto || false);
    } else if (options.component) {
      await setupComponent(options.component, options.auto || false);
    } else {
      await interactiveSetup(connectionManager);
    }
  } catch (error) {
    logger.error(`Setup failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    process.exit(1);
  } finally {
    await connectionManager.disconnect();
  }
}

async function interactiveSetup(connectionManager: ConnectionManager): Promise<void> {
  console.log(chalk.gray('Analyzing your current environment...\\n'));
  
  const environmentStatus = await connectionManager.checkEnvironmentStatus();
  
  // Show current status
  console.log(chalk.blue('📊 Current Environment Status:'));
  for (const connection of environmentStatus.connections) {
    const statusIcon = connection.status === 'connected' ? '✅' : 
                      connection.status === 'degraded' ? '⚠️' : '❌';
    console.log(`  ${statusIcon} ${connection.component}: ${connection.status}`);
  }
  
  console.log('\\n');
  
  // Detect platform
  const detectedPlatform = await detectPlatform();
  if (detectedPlatform) {
    console.log(chalk.green(`🔍 Detected platform: ${detectedPlatform}`));
  }
  
  // Show what needs to be set up
  const missingComponents = environmentStatus.connections
    .filter(c => c.status === 'unavailable' || c.status === 'not_configured')
    .map(c => c.component);
    
  if (missingComponents.length === 0) {
    console.log(chalk.green('\\n🎉 All components are already configured!'));
    console.log(chalk.gray('Your A2A platform is ready to use.'));
    return;
  }
  
  console.log(chalk.yellow(`\\n⚠️ Missing components: ${missingComponents.join(', ')}`));
  
  // Ask what to set up
  const { setupChoice } = await inquirer.prompt([
    {
      type: 'list',
      name: 'setupChoice',
      message: 'What would you like to do?',
      choices: [
        { name: 'Auto-setup all missing components', value: 'auto-all' },
        { name: 'Choose specific components to setup', value: 'choose' },
        { name: 'Show platform-specific setup guide', value: 'guide' },
        { name: 'Exit setup', value: 'exit' }
      ]
    }
  ]);
  
  switch (setupChoice) {
    case 'auto-all':
      await autoSetupMissingComponents(missingComponents);
      break;
    case 'choose':
      await chooseComponentsSetup(missingComponents);
      break;
    case 'guide':
      await showPlatformGuide(detectedPlatform);
      break;
    case 'exit':
      console.log(chalk.gray('Setup cancelled.'));
      break;
  }
}

async function detectPlatform(): Promise<string | null> {
  try {
    // Check if running in cloud environment
    
    // AWS detection
    try {
      await execAsync('curl -s -m 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null');
      return 'aws';
    } catch {
      // Not AWS
    }
    
    // GCP detection
    try {
      const { stdout } = await execAsync('curl -s -m 2 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/project-id 2>/dev/null');
      if (stdout) return 'gcp';
    } catch {
      // Not GCP
    }
    
    // Azure detection
    try {
      await execAsync('curl -s -m 2 -H "Metadata:true" http://169.254.169.254/metadata/instance?api-version=2021-02-01 2>/dev/null');
      return 'azure';
    } catch {
      // Not Azure
    }
    
    // Check kubectl context for platform hints
    try {
      const { stdout } = await execAsync('kubectl config current-context 2>/dev/null');
      const context = stdout.trim().toLowerCase();
      
      if (context.includes('eks') || context.includes('amazon')) {
        return 'aws-eks';
      } else if (context.includes('gke') || context.includes('google')) {
        return 'gcp-gke';
      } else if (context.includes('aks') || context.includes('azure')) {
        return 'azure-aks';
      } else if (context.includes('minikube')) {
        return 'minikube';
      } else if (context.includes('k3s')) {
        return 'k3s';
      }
    } catch {
      // No kubectl context
    }
    
    // Check if Docker Desktop is running
    try {
      const { stdout } = await execAsync('docker info 2>/dev/null | grep "Operating System"');
      if (stdout.includes('Docker Desktop')) {
        return 'docker-desktop';
      }
    } catch {
      // Docker not available
    }
    
    return 'local';
  } catch {
    return null;
  }
}

async function autoSetupMissingComponents(components: string[]): Promise<void> {
  console.log(chalk.blue('\\n🤖 Auto-setup Mode'));
  console.log(chalk.gray('This will attempt to automatically install and configure missing components.\\n'));
  
  for (const component of components) {
    const spinner = ora(`Setting up ${component}...`).start();
    
    try {
      const success = await setupComponentAuto(component);
      if (success) {
        spinner.succeed(`${component} setup completed`);
      } else {
        spinner.warn(`${component} setup partially completed - manual steps required`);
      }
    } catch (error) {
      spinner.fail(`${component} setup failed`);
      console.log(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
    }
  }
  
  // Final verification
  console.log(chalk.blue('\\n🔍 Verifying setup...'));
  const connectionManager = new ConnectionManager();
  const finalStatus = await connectionManager.checkEnvironmentStatus();
  
  const stillMissing = finalStatus.connections
    .filter(c => c.status === 'unavailable' || c.status === 'not_configured')
    .map(c => c.component);
    
  if (stillMissing.length === 0) {
    console.log(chalk.green('\\n🎉 Setup completed successfully!'));
    console.log(chalk.gray('All components are now configured and ready to use.'));
  } else {
    console.log(chalk.yellow(`\\n⚠️ Setup partially completed. Still missing: ${stillMissing.join(', ')}`));
    console.log(chalk.gray('Run setup again or check the manual setup guide.'));
  }
}

async function setupComponentAuto(component: string): Promise<boolean> {
  switch (component) {
    case 'kubernetes':
      return await setupKubernetes();
    case 'falco':
      return await setupFalco();
    case 'prometheus':
      return await setupPrometheus();
    case 'alertmanager':
      return await setupAlertmanager();
    default:
      throw new Error(`Unknown component: ${component}`);
  }
}

async function setupKubernetes(): Promise<boolean> {
  // Check if kubectl is installed
  try {
    await execAsync('kubectl version --client 2>/dev/null');
  } catch {
    console.log(chalk.yellow('kubectl not found. Please install kubectl manually:'));
    console.log(chalk.gray('  https://kubernetes.io/docs/tasks/tools/'));
    return false;
  }
  
  // Check if there's a kubeconfig
  const kubeconfigPaths = [
    process.env.KUBECONFIG,
    path.join(process.env.HOME || process.env.USERPROFILE || '', '.kube', 'config')
  ].filter(Boolean);
  
  const hasKubeconfig = kubeconfigPaths.some(p => p && existsSync(p));
  
  if (!hasKubeconfig) {
    console.log(chalk.yellow('No kubeconfig found. Please configure cluster access:'));
    console.log(chalk.gray('  AWS EKS: aws eks update-kubeconfig --name <cluster-name>'));
    console.log(chalk.gray('  GCP GKE: gcloud container clusters get-credentials <cluster-name>'));
    console.log(chalk.gray('  Azure AKS: az aks get-credentials --name <cluster-name> --resource-group <rg>'));
    return false;
  }
  
  // Test connectivity
  try {
    const stderrRedirect = process.platform === 'win32' ? '2>nul' : '2>/dev/null';
    await execAsync(`kubectl cluster-info --request-timeout=10s ${stderrRedirect}`);
    return true;
  } catch {
    console.log(chalk.yellow('kubeconfig found but cluster not accessible. Check your cluster status.'));
    return false;
  }
}

async function setupFalco(): Promise<boolean> {
  const platform = process.platform;
  
  try {
    if (platform === 'linux') {
      // Install Falco on Linux
      console.log(chalk.gray('Installing Falco...'));
      await execAsync('curl -s https://falco.org/script/install | sudo bash');
      await execAsync('sudo systemctl enable falco');
      await execAsync('sudo systemctl start falco');
      
      // Wait a bit for startup
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      // Verify
      await execAsync('sudo systemctl is-active falco');
      return true;
      
    } else {
      // For non-Linux, suggest Docker
      console.log(chalk.yellow('Falco native installation not supported on this platform.'));
      console.log(chalk.gray('Consider using Docker:'));
      console.log(chalk.gray('  docker run -i -t \\\\'));
      console.log(chalk.gray('    --name falco \\\\'));
      console.log(chalk.gray('    --privileged \\\\'));
      console.log(chalk.gray('    -v /var/run/docker.sock:/host/var/run/docker.sock \\\\'));
      console.log(chalk.gray('    -v /dev:/host/dev \\\\'));
      console.log(chalk.gray('    -v /proc:/host/proc:ro \\\\'));
      console.log(chalk.gray('    -v /boot:/host/boot:ro \\\\'));
      console.log(chalk.gray('    -v /lib/modules:/host/lib/modules:ro \\\\'));
      console.log(chalk.gray('    -v /usr:/host/usr:ro \\\\'));
      console.log(chalk.gray('    -v /etc:/host/etc:ro \\\\'));
      console.log(chalk.gray('    falcosecurity/falco:latest'));
      return false;
    }
  } catch (error) {
    console.log(chalk.red(`Falco installation failed: ${error instanceof Error ? error.message : 'Unknown error'}`));
    return false;
  }
}

async function setupPrometheus(): Promise<boolean> {
  try {
    const platform = process.platform;
    
    if (platform === 'darwin') {
      // macOS with Homebrew
      try {
        await execAsync('brew --version 2>/dev/null');
        console.log(chalk.gray('Installing Prometheus via Homebrew...'));
        await execAsync('brew install prometheus');
        
        // Create basic config
        const configPath = '/usr/local/etc/prometheus.yml';
        const basicConfig = `
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
`;
        
        if (!existsSync(configPath)) {
          await writeFile(configPath, basicConfig);
        }
        
        // Start service
        await execAsync('brew services start prometheus');
        return true;
        
      } catch {
        console.log(chalk.yellow('Homebrew not found. Please install Prometheus manually.'));
        return false;
      }
      
    } else if (platform === 'linux') {
      // Linux installation
      console.log(chalk.gray('Installing Prometheus...'));
      
      const prometheusVersion = '2.45.0';
      const downloadUrl = `https://github.com/prometheus/prometheus/releases/download/v${prometheusVersion}/prometheus-${prometheusVersion}.linux-amd64.tar.gz`;
      
      await execAsync(`cd /tmp && wget ${downloadUrl}`);
      await execAsync(`cd /tmp && tar xvfz prometheus-${prometheusVersion}.linux-amd64.tar.gz`);
      await execAsync(`sudo cp /tmp/prometheus-${prometheusVersion}.linux-amd64/prometheus /usr/local/bin/`);
      await execAsync(`sudo cp /tmp/prometheus-${prometheusVersion}.linux-amd64/promtool /usr/local/bin/`);
      
      // Create basic config
      const configDir = '/etc/prometheus';
      await execAsync(`sudo mkdir -p ${configDir}`);
      
      const basicConfig = `
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
`;
      
      await execAsync(`echo '${basicConfig}' | sudo tee ${configDir}/prometheus.yml`);
      
      // Create systemd service
      const serviceConfig = `
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \\
    --config.file /etc/prometheus/prometheus.yml \\
    --storage.tsdb.path /var/lib/prometheus/ \\
    --web.console.templates=/etc/prometheus/consoles \\
    --web.console.libraries=/etc/prometheus/console_libraries \\
    --web.listen-address=0.0.0.0:9090 \\
    --web.enable-lifecycle

[Install]
WantedBy=multi-user.target
`;
      
      await execAsync(`echo '${serviceConfig}' | sudo tee /etc/systemd/system/prometheus.service`);
      await execAsync('sudo useradd --no-create-home --shell /bin/false prometheus || true');
      await execAsync('sudo mkdir -p /var/lib/prometheus');
      await execAsync('sudo chown prometheus:prometheus /var/lib/prometheus');
      await execAsync('sudo systemctl daemon-reload');
      await execAsync('sudo systemctl enable prometheus');
      await execAsync('sudo systemctl start prometheus');
      
      return true;
      
    } else {
      console.log(chalk.yellow('Auto-installation not supported on this platform.'));
      console.log(chalk.gray('Please download Prometheus from: https://prometheus.io/download/'));
      return false;
    }
    
  } catch (error) {
    console.log(chalk.red(`Prometheus installation failed: ${error instanceof Error ? error.message : 'Unknown error'}`));
    return false;
  }
}

async function setupAlertmanager(): Promise<boolean> {
  try {
    const platform = process.platform;
    
    if (platform === 'darwin') {
      // macOS with Homebrew
      try {
        await execAsync('brew --version 2>/dev/null');
        console.log(chalk.gray('Installing Alertmanager via Homebrew...'));
        await execAsync('brew install alertmanager');
        
        // Create basic config
        const configPath = '/usr/local/etc/alertmanager.yml';
        const basicConfig = `
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alertmanager@localhost'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
- name: 'web.hook'
  webhook_configs:
  - url: 'http://127.0.0.1:5001/'
`;
        
        if (!existsSync(configPath)) {
          await writeFile(configPath, basicConfig);
        }
        
        // Start service
        await execAsync('brew services start alertmanager');
        return true;
        
      } catch {
        console.log(chalk.yellow('Homebrew not found. Please install Alertmanager manually.'));
        return false;
      }
      
    } else {
      console.log(chalk.yellow('Auto-installation not supported on this platform.'));
      console.log(chalk.gray('Please download Alertmanager from: https://prometheus.io/download/'));
      return false;
    }
    
  } catch (error) {
    console.log(chalk.red(`Alertmanager installation failed: ${error instanceof Error ? error.message : 'Unknown error'}`));
    return false;
  }
}

async function chooseComponentsSetup(missingComponents: string[]): Promise<void> {
  const { selectedComponents } = await inquirer.prompt([
    {
      type: 'checkbox',
      name: 'selectedComponents',
      message: 'Select components to set up:',
      choices: missingComponents.map(comp => ({ name: comp, value: comp }))
    }
  ]);
  
  if (selectedComponents.length === 0) {
    console.log(chalk.gray('No components selected.'));
    return;
  }
  
  await autoSetupMissingComponents(selectedComponents);
}

async function showSetupGuide(connectionManager: ConnectionManager): Promise<void> {
  const environmentStatus = await connectionManager.checkEnvironmentStatus();
  const setupInstructions = connectionManager.generateSetupGuide();
  
  console.log(chalk.blue('📖 Setup Guide'));
  console.log(chalk.blue('=' .repeat(40)));
  
  if (setupInstructions.length === 0) {
    console.log(chalk.green('🎉 All components are properly configured!'));
    return;
  }
  
  setupInstructions.forEach(instruction => {
    console.log(instruction);
  });
  
  console.log(chalk.blue('\\n🔧 Additional Resources:'));
  console.log(chalk.gray('  • A2A Documentation: https://docs.a2a-cli.dev'));
  console.log(chalk.gray('  • Kubernetes Setup: https://kubernetes.io/docs/setup/'));
  console.log(chalk.gray('  • Falco Installation: https://falco.org/docs/getting-started/installation/'));
  console.log(chalk.gray('  • Prometheus Setup: https://prometheus.io/docs/prometheus/latest/getting_started/'));
}

async function setupPlatform(platform: string, auto: boolean): Promise<void> {
  console.log(chalk.blue(`🚀 Setting up for ${platform.toUpperCase()}`));
  console.log(chalk.blue('=' .repeat(50)));
  
  const guide = getPlatformGuide(platform);
  
  if (!guide) {
    console.log(chalk.red(`❌ Platform '${platform}' not supported`));
    console.log(chalk.gray('Supported platforms: aws-eks, gcp-gke, azure-aks, minikube, local'));
    return;
  }
  
  console.log(chalk.gray(guide.description));
  console.log('\\n');
  
  if (guide.prerequisites.length > 0) {
    console.log(chalk.yellow('📋 Prerequisites:'));
    guide.prerequisites.forEach(prereq => {
      console.log(chalk.gray(`  • ${prereq}`));
    });
    console.log('\\n');
  }
  
  if (auto) {
    console.log(chalk.blue('🤖 Auto-execution mode\\n'));
    
    for (const step of guide.steps) {
      if (step.autoExecute) {
        const spinner = ora(step.name).start();
        
        try {
          for (const command of step.commands) {
            await execAsync(command);
          }
          
          const isValid = await step.validation();
          if (isValid) {
            spinner.succeed(step.name);
          } else {
            spinner.warn(`${step.name} - Manual verification required`);
          }
        } catch (error) {
          spinner.fail(`${step.name} - Failed`);
          console.log(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
        }
      } else {
        console.log(chalk.yellow(`⚠️ Manual step: ${step.name}`));
        console.log(chalk.gray(`   ${step.description}`));
      }
    }
  } else {
    console.log(chalk.blue('📋 Setup Steps:\\n'));
    
    guide.steps.forEach((step, index) => {
      console.log(chalk.cyan(`${index + 1}. ${step.name}`));
      console.log(chalk.gray(`   ${step.description}`));
      
      if (step.commands.length > 0) {
        console.log(chalk.gray('   Commands:'));
        step.commands.forEach(cmd => {
          console.log(chalk.gray(`     ${cmd}`));
        });
      }
      console.log('');
    });
  }
}

function getPlatformGuide(platform: string): SetupGuide | null {
  const guides: Record<string, SetupGuide> = {
    'aws-eks': {
      platform: 'AWS EKS',
      description: 'Setup for Amazon Elastic Kubernetes Service',
      prerequisites: [
        'AWS CLI installed and configured',
        'kubectl installed',
        'Appropriate IAM permissions'
      ],
      steps: [
        {
          name: 'Update kubeconfig',
          description: 'Configure kubectl to connect to your EKS cluster',
          commands: ['aws eks update-kubeconfig --name <cluster-name> --region <region>'],
          validation: async () => {
            try {
              await execAsync('kubectl cluster-info --request-timeout=10s');
              return true;
            } catch { return false; }
          }
        },
        {
          name: 'Install Falco via Helm',
          description: 'Deploy Falco for security monitoring',
          commands: [
            'helm repo add falcosecurity https://falcosecurity.github.io/charts',
            'helm repo update',
            'helm install falco falcosecurity/falco --namespace falco-system --create-namespace'
          ],
          validation: async () => {
            try {
              await execAsync('kubectl get pods -n falco-system');
              return true;
            } catch { return false; }
          },
          autoExecute: true
        }
      ]
    },
    
    'gcp-gke': {
      platform: 'Google GKE',
      description: 'Setup for Google Kubernetes Engine',
      prerequisites: [
        'Google Cloud SDK installed',
        'kubectl installed',
        'Authenticated with gcloud'
      ],
      steps: [
        {
          name: 'Get cluster credentials',
          description: 'Configure kubectl for GKE cluster',
          commands: ['gcloud container clusters get-credentials <cluster-name> --zone <zone>'],
          validation: async () => {
            try {
              await execAsync('kubectl cluster-info --request-timeout=10s');
              return true;
            } catch { return false; }
          }
        }
      ]
    },
    
    'local': {
      platform: 'Local Development',
      description: 'Setup for local development environment',
      prerequisites: [
        'Docker installed',
        'kubectl installed'
      ],
      steps: [
        {
          name: 'Install Minikube',
          description: 'Local Kubernetes cluster',
          commands: [
            'curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64',
            'sudo install minikube-linux-amd64 /usr/local/bin/minikube'
          ],
          validation: async () => {
            try {
              await execAsync('minikube version');
              return true;
            } catch { return false; }
          },
          autoExecute: true
        }
      ]
    }
  };
  
  return guides[platform] || null;
}

async function showPlatformGuide(platform: string | null): Promise<void> {
  if (!platform) {
    console.log(chalk.yellow('Platform not detected. Showing general setup guide.'));
    platform = 'local';
  }
  
  await setupPlatform(platform, false);
}

async function setupComponent(component: string, auto: boolean): Promise<void> {
  console.log(chalk.blue(`🔧 Setting up ${component}`));
  console.log(chalk.blue('=' .repeat(30)));
  
  try {
    const success = await setupComponentAuto(component);
    
    if (success) {
      console.log(chalk.green(`\\n✅ ${component} setup completed successfully!`));
    } else {
      console.log(chalk.yellow(`\\n⚠️ ${component} setup requires manual steps`));
    }
  } catch (error) {
    console.log(chalk.red(`\\n❌ ${component} setup failed`));
    console.log(chalk.red(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`));
  }
}