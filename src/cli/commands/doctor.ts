import { exec } from 'child_process';
import { promisify } from 'util';
import chalk from 'chalk';
import ora from 'ora';
import { Logger } from '../utils/logger';
import { existsSync } from 'fs';
import { writeFile } from 'fs/promises';

const execAsync = promisify(exec);
const logger = Logger.getInstance();

export interface DoctorOptions {
  fix?: boolean;
  check?: string;
  export?: string;
}

interface HealthCheck {
  name: string;
  status: 'ok' | 'warning' | 'error' | 'unknown';
  message: string;
  details?: string;
  fixable?: boolean;
  fix?: () => Promise<void>;
}

export async function doctorCommand(options: DoctorOptions): Promise<void> {
  console.log(chalk.blue('🏥 A2A System Health Check'));
  console.log(chalk.blue('=' .repeat(40)));

  const checks: HealthCheck[] = [];
  const components = options.check ? [options.check] : ['node', 'claude', 'falco', 'prometheus', 'k8s', 'docker'];

  for (const component of components) {
    const spinner = ora(`Checking ${component}...`).start();
    
    try {
      const check = await performComponentCheck(component);
      checks.push(check);
      
      if (check.status === 'ok') {
        spinner.succeed(`${check.name}: ${chalk.green(check.message)}`);
      } else if (check.status === 'warning') {
        spinner.warn(`${check.name}: ${chalk.yellow(check.message)}`);
      } else if (check.status === 'error') {
        spinner.fail(`${check.name}: ${chalk.red(check.message)}`);
      } else {
        spinner.info(`${check.name}: ${chalk.gray(check.message)}`);
      }

      if (check.details && process.env.A2A_DEBUG === 'true') {
        console.log(chalk.gray(`   ${check.details}`));
      }

    } catch (error) {
      spinner.fail(`${component}: ${chalk.red('Check failed')}`);
      checks.push({
        name: component,
        status: 'error',
        message: `Health check failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      });
    }
  }

  // Show summary
  console.log('\\n' + chalk.blue('📊 Health Check Summary'));
  console.log(chalk.blue('-'.repeat(30)));

  const okCount = checks.filter(c => c.status === 'ok').length;
  const warningCount = checks.filter(c => c.status === 'warning').length;
  const errorCount = checks.filter(c => c.status === 'error').length;

  console.log(`✅ Healthy: ${chalk.green(okCount)}`);
  console.log(`⚠️  Warnings: ${chalk.yellow(warningCount)}`);
  console.log(`❌ Errors: ${chalk.red(errorCount)}`);

  // Show fixable issues
  const fixableIssues = checks.filter(c => c.fixable && c.status !== 'ok');
  if (fixableIssues.length > 0) {
    console.log('\\n' + chalk.yellow('🔧 Fixable Issues:'));
    fixableIssues.forEach(issue => {
      console.log(`  • ${issue.name}: ${issue.message}`);
    });

    if (options.fix) {
      console.log('\\n' + chalk.blue('🛠️  Attempting to fix issues...'));
      for (const issue of fixableIssues) {
        if (issue.fix) {
          const fixSpinner = ora(`Fixing ${issue.name}...`).start();
          try {
            await issue.fix();
            fixSpinner.succeed(`Fixed ${issue.name}`);
          } catch (error) {
            fixSpinner.fail(`Failed to fix ${issue.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
          }
        }
      }
    } else {
      console.log(chalk.gray('  Run with --fix to attempt automatic fixes'));
    }
  }

  // Show recommendations
  const recommendations = generateRecommendations(checks);
  if (recommendations.length > 0) {
    console.log('\\n' + chalk.magenta('💡 Recommendations:'));
    recommendations.forEach((rec, index) => {
      console.log(`  ${index + 1}. ${rec}`);
    });
  }

  // Export report if requested
  if (options.export) {
    await exportHealthReport(checks, options.export);
    logger.info(`📄 Health report exported to ${options.export}`);
  }

  // Exit with appropriate code
  if (errorCount > 0) {
    process.exit(1);
  } else if (warningCount > 0) {
    process.exit(2);
  }
}

async function performComponentCheck(component: string): Promise<HealthCheck> {
  switch (component.toLowerCase()) {
    case 'node':
      return await checkNodeJs();
    case 'claude':
      return await checkClaudeCode();
    case 'falco':
      return await checkFalco();
    case 'prometheus':
      return await checkPrometheus();
    case 'k8s':
    case 'kubernetes':
      return await checkKubernetes();
    case 'docker':
      return await checkDocker();
    default:
      return {
        name: component,
        status: 'unknown',
        message: `Unknown component: ${component}`
      };
  }
}

async function checkNodeJs(): Promise<HealthCheck> {
  try {
    const { stdout } = await execAsync('node --version');
    const version = stdout.trim();
    const majorVersion = parseInt(version.replace('v', '').split('.')[0]);

    if (majorVersion >= 18) {
      return {
        name: 'Node.js',
        status: 'ok',
        message: `${version} (compatible)`,
        details: `Node.js version is ${version}, which meets the minimum requirement of v18.0.0`
      };
    } else {
      return {
        name: 'Node.js',
        status: 'error',
        message: `${version} (requires v18.0.0+)`,
        details: 'Please upgrade Node.js to version 18.0.0 or higher',
        fixable: false
      };
    }
  } catch (error) {
    return {
      name: 'Node.js',
      status: 'error',
      message: 'Not installed or not in PATH',
      fixable: false
    };
  }
}

async function checkClaudeCode(): Promise<HealthCheck> {
  try {
    const { stdout } = await execAsync('claude --version');
    const version = stdout.split('\n')[0].replace('Client Version: ', '').trim();

    return {
      name: 'Claude Code',
      status: 'ok',
      message: `${version} (installed)`,
      details: 'Claude Code is installed. Authentication will be verified when you run queries.'
    };
  } catch (error) {
    return {
      name: 'Claude Code',
      status: 'error',
      message: 'Not installed or not in PATH',
      details: 'Install Claude Code from: https://docs.anthropic.com/claude-code',
      fixable: false
    };
  }
}

async function checkFalco(): Promise<HealthCheck> {
  // First check for Kubernetes Pod installation
  try {
    const { stdout: podOutput } = await execAsync('kubectl get pods -n falco-system -l app=falco --no-headers');
    if (podOutput.trim()) {
      const pods = podOutput.trim().split('\n');
      const runningPods = pods.filter(line => line.includes('Running') || line.includes('CrashLoopBackOff'));
      
      if (runningPods.length > 0) {
        const podStatus = runningPods[0].includes('Running') ? 'running' : 'starting';
        return {
          name: 'Falco',
          status: 'ok',
          message: `Kubernetes Pod (${podStatus})`,
          details: `Falco is running as Kubernetes Pod in falco-system namespace. Pods: ${pods.length}`
        };
      }
    }
  } catch {
    // If kubectl fails, continue to other checks
  }

  // Check for binary installation
  try {
    const { stdout } = await execAsync('falco --version');
    const version = stdout.trim();

    // Check if Falco is running
    try {
      await execAsync('systemctl is-active falco');
      return {
        name: 'Falco',
        status: 'ok',
        message: `${version} (running)`,
        details: 'Falco is installed and running as a service'
      };
    } catch {
      // Check if running in Docker
      try {
        const { stdout: dockerOutput } = await execAsync('docker ps --filter name=falco --quiet');
        if (dockerOutput.trim()) {
          return {
            name: 'Falco',
            status: 'ok',
            message: `${version} (running in Docker)`,
            details: 'Falco is running as a Docker container'
          };
        } else {
          return {
            name: 'Falco',
            status: 'warning',
            message: `${version} (not running)`,
            details: 'Falco is installed but not running. Start with: sudo systemctl start falco',
            fixable: true,
            fix: async () => {
              await execAsync('sudo systemctl start falco');
            }
          };
        }
      } catch {
        return {
          name: 'Falco',
          status: 'warning',
          message: `${version} (status unknown)`,
          details: 'Cannot determine if Falco is running'
        };
      }
    }
  } catch (error) {
    return {
      name: 'Falco',
      status: 'error',
      message: 'Not installed',
      details: 'Install Falco from: https://falco.org/docs/getting-started/installation/',
      fixable: false
    };
  }
}

async function checkPrometheus(): Promise<HealthCheck> {
  try {
    // Check if Prometheus is accessible via HTTP
    const axios = await import('axios');
    const response = await axios.default.get('http://localhost:9090/-/healthy', { timeout: 5000 });
    
    if (response.status === 200) {
      // Get version info
      try {
        const buildInfoResponse = await axios.default.get('http://localhost:9090/api/v1/query', {
          params: { query: 'prometheus_build_info' },
          timeout: 5000
        });
        
        const version = buildInfoResponse.data.data.result[0]?.metric?.version || 'unknown';
        return {
          name: 'Prometheus',
          status: 'ok',
          message: `v${version} (accessible at :9090)`,
          details: 'Prometheus is running and accessible'
        };
      } catch {
        return {
          name: 'Prometheus',
          status: 'ok',
          message: 'Running (version unknown)',
          details: 'Prometheus is accessible at http://localhost:9090'
        };
      }
    }
  } catch (error) {
    // Check if it's installed but not running
    try {
      await execAsync('prometheus --version');
      return {
        name: 'Prometheus',
        status: 'warning',
        message: 'Installed but not accessible',
        details: 'Prometheus is installed but not accessible at http://localhost:9090',
        fixable: true,
        fix: async () => {
          console.log('Please start Prometheus server or check configuration');
        }
      };
    } catch {
      return {
        name: 'Prometheus',
        status: 'error',
        message: 'Not installed',
        details: 'Install Prometheus from: https://prometheus.io/download/',
        fixable: false
      };
    }
  }

  return {
    name: 'Prometheus',
    status: 'error',
    message: 'Not accessible',
    details: 'Cannot reach Prometheus at http://localhost:9090'
  };
}

async function checkKubernetes(): Promise<HealthCheck> {
  try {
    const { stdout } = await execAsync('kubectl version --client');
    const clientVersion = stdout.split('\n')[0].replace('Client Version: ', '');

    try {
      const { stdout: serverStdout } = await execAsync('kubectl cluster-info');
      const clusterInfo = serverStdout.includes('running at');
      
      if (clusterInfo) {
        return {
          name: 'Kubernetes',
          status: 'ok',
          message: `${clientVersion} (cluster connected)`,
          details: 'kubectl is configured and connected to a cluster'
        };
      } else {
        return {
          name: 'Kubernetes',
          status: 'warning',
          message: `${clientVersion} (no cluster connection)`,
          details: 'kubectl is installed but not connected to a cluster'
        };
      }
    } catch {
      return {
        name: 'Kubernetes',
        status: 'warning',
        message: `${clientVersion} (no cluster connection)`,
        details: 'kubectl is installed but cannot connect to a cluster'
      };
    }
  } catch (error) {
    return {
      name: 'Kubernetes',
      status: 'error',
      message: 'kubectl not installed',
      details: 'Install kubectl from: https://kubernetes.io/docs/tasks/tools/',
      fixable: false
    };
  }
}

async function checkDocker(): Promise<HealthCheck> {
  try {
    const { stdout } = await execAsync('docker --version');
    const version = stdout.trim();

    try {
      await execAsync('docker ps');
      return {
        name: 'Docker',
        status: 'ok',
        message: `${version} (daemon running)`,
        details: 'Docker is installed and daemon is running'
      };
    } catch {
      return {
        name: 'Docker',
        status: 'warning',
        message: `${version} (daemon not running)`,
        details: 'Docker is installed but daemon is not running or not accessible',
        fixable: true,
        fix: async () => {
          console.log('Please start Docker daemon');
        }
      };
    }
  } catch (error) {
    return {
      name: 'Docker',
      status: 'error',
      message: 'Not installed',
      details: 'Install Docker from: https://docs.docker.com/get-docker/',
      fixable: false
    };
  }
}

function generateRecommendations(checks: HealthCheck[]): string[] {
  const recommendations: string[] = [];

  const errorChecks = checks.filter(c => c.status === 'error');
  const warningChecks = checks.filter(c => c.status === 'warning');

  if (errorChecks.some(c => c.name === 'Claude Code')) {
    recommendations.push('Install Claude Code CLI to enable AI-powered query routing');
  }

  if (errorChecks.some(c => c.name === 'Falco')) {
    recommendations.push('Install Falco for runtime security monitoring capabilities');
  }

  if (errorChecks.some(c => c.name === 'Prometheus')) {
    recommendations.push('Install Prometheus for metrics collection and monitoring');
  }

  if (warningChecks.some(c => c.name.includes('not running'))) {
    recommendations.push('Start required services for full A2A functionality');
  }

  if (checks.filter(c => c.status === 'ok').length === checks.length) {
    recommendations.push('All systems operational! A2A is ready for use');
  }

  if (recommendations.length === 0 && (errorChecks.length > 0 || warningChecks.length > 0)) {
    recommendations.push('Review the issues above and install missing dependencies');
    recommendations.push('Run a2a doctor --fix to attempt automatic fixes where possible');
  }

  return recommendations;
}

async function exportHealthReport(checks: HealthCheck[], format: string): Promise<void> {
  const report = {
    timestamp: new Date().toISOString(),
    system: process.platform,
    node_version: process.version,
    checks,
    summary: {
      total: checks.length,
      healthy: checks.filter(c => c.status === 'ok').length,
      warnings: checks.filter(c => c.status === 'warning').length,
      errors: checks.filter(c => c.status === 'error').length
    }
  };

  let content: string;

  switch (format.toLowerCase()) {
    case 'json':
      content = JSON.stringify(report, null, 2);
      break;
    case 'yaml':
      const yaml = await import('yaml');
      content = yaml.stringify(report);
      break;
    case 'html':
      content = generateHtmlReport(report);
      break;
    default:
      content = JSON.stringify(report, null, 2);
      break;
  }

  await writeFile(format, content, 'utf8');
}

function generateHtmlReport(report: any): string {
  return `<!DOCTYPE html>
<html>
<head>
    <title>A2A System Health Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .ok { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        .unknown { color: gray; }
        .check { margin: 10px 0; padding: 10px; border-left: 4px solid #ddd; }
        .summary { background: #f5f5f5; padding: 20px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>A2A System Health Report</h1>
    <p>Generated: ${report.timestamp}</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Checks: ${report.summary.total}</p>
        <p class="ok">✅ Healthy: ${report.summary.healthy}</p>
        <p class="warning">⚠️ Warnings: ${report.summary.warnings}</p>
        <p class="error">❌ Errors: ${report.summary.errors}</p>
    </div>

    <h2>Detailed Results</h2>
    ${report.checks.map((check: HealthCheck) => `
        <div class="check">
            <h3 class="${check.status}">${check.name}</h3>
            <p><strong>Status:</strong> <span class="${check.status}">${check.status.toUpperCase()}</span></p>
            <p><strong>Message:</strong> ${check.message}</p>
            ${check.details ? `<p><strong>Details:</strong> ${check.details}</p>` : ''}
        </div>
    `).join('')}
</body>
</html>`;
}