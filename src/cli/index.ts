#!/usr/bin/env node

import { Command } from 'commander';
import { queryCommand } from './commands/query';
import { monitorCommand } from './commands/monitor';
import { serveCommand } from './commands/serve';
import { doctorCommand } from './commands/doctor';
import { configCommand } from './commands/config';
import { validateCommand, validateCategories, validateMode } from './commands/validate';
import { clusterCommand } from './commands/cluster';
import { setupCommand } from './commands/setup';
import { statusCommand } from './commands/status';
import { Logger } from './utils/logger';

const program = new Command();
const logger = Logger.getInstance();

// Global CLI configuration
program
  .name('a2a')
  .description('A2A DevOps Platform - Natural language control of DevOps operations through AI-powered agents')
  .version('1.0.0')
  .option('-d, --debug', 'Enable debug output')
  .option('-v, --verbose', 'Enable verbose output')
  .option('--dry-run', 'Simulate operations without executing them')
  .option('--config <path>', 'Path to configuration file')
  .hook('preAction', (thisCommand) => {
    const options = thisCommand.opts();
    
    // Set up logger based on CLI options
    if (options.debug) {
      logger.setLevel('debug');
      process.env.A2A_DEBUG = 'true';
    } else if (options.verbose) {
      logger.setLevel('verbose');
    }

    if (options.dryRun) {
      process.env.A2A_DRY_RUN = 'true';
      logger.info('🧪 Running in dry-run mode');
    }

    if (options.config) {
      process.env.A2A_CONFIG_PATH = options.config;
    }
  });

// Main query command - the primary interface for natural language queries
program
  .command('query')
  .alias('q')
  .description('Process natural language queries using AI-powered agent routing')
  .argument('<query>', 'Natural language query to process')
  .option('-f, --format <type>', 'Output format', 'text')
  .option('-a, --agent <name>', 'Force routing to specific agent (falco, prometheus, general)')
  .option('-o, --output <file>', 'Save output to file')
  .option('--timeout <seconds>', 'Query timeout in seconds', '30')
  .option('--no-cache', 'Disable query result caching')
  .action(queryCommand);

// Real-time monitoring command
program
  .command('monitor')
  .alias('m')
  .description('Start real-time security and performance monitoring')
  .option('-s, --severity <level>', 'Minimum severity level (low, medium, high, critical)', 'medium')
  .option('-n, --namespace <name>', 'Kubernetes namespace to monitor')
  .option('--notify <channel>', 'Notification channel (slack, pagerduty, email)')
  .option('--interval <seconds>', 'Monitoring interval in seconds', '60')
  .option('--daemon', 'Run as background daemon')
  .option('--pid-file <path>', 'PID file path for daemon mode')
  .action(monitorCommand);

// Web UI server command
program
  .command('serve')
  .alias('s')
  .description('Start the web UI server for visualization and monitoring')
  .option('-p, --port <number>', 'Server port', '3000')
  .option('--host <address>', 'Server host', 'localhost')
  .option('--api-only', 'Serve API only without web UI')
  .option('--cors', 'Enable CORS for cross-origin requests')
  .option('--ssl-cert <path>', 'SSL certificate file path')
  .option('--ssl-key <path>', 'SSL private key file path')
  .action(serveCommand);

// System health and dependency checker
program
  .command('doctor')
  .alias('dr')
  .description('Check system dependencies and configuration')
  .option('--fix', 'Attempt to fix detected issues automatically')
  .option('--check <component>', 'Check specific component (falco, prometheus, claude, k8s)')
  .option('--export <format>', 'Export health report (json, yaml, html)')
  .action(doctorCommand);

// Security checklist validation
program
  .command('validate')
  .alias('val')
  .description('Execute comprehensive security checklist validation')
  .option('-c, --categories <categories...>', 'Security categories to test', (value, previous) => {
    const cats = value.split(',').map((s: string) => s.trim());
    if (!validateCategories(cats)) {
      console.error('Invalid categories. Valid options: filesystem, process, network, privilege, container, kubernetes');
      process.exit(1);
    }
    return cats;
  })
  .option('-m, --mode <mode>', 'Test mode (safe, aggressive, simulation)', (value) => {
    if (!validateMode(value)) {
      console.error('Invalid mode. Valid options: safe, aggressive, simulation');
      process.exit(1);
    }
    return value;
  })
  .option('-t, --timeout <ms>', 'Timeout per test in milliseconds')
  .option('-p, --parallel', 'Run tests in parallel')
  .option('-r, --no-report', 'Skip generating detailed report')
  .option('-o, --output <dir>', 'Output directory for logs and reports')
  .option('-v, --verbose', 'Enable verbose logging')
  .action(validateCommand);

// Configuration management commands
const configCmd = program
  .command('config')
  .description('Manage A2A configuration');

configCmd
  .command('init')
  .description('Initialize A2A configuration')
  .option('--force', 'Overwrite existing configuration')
  .action(configCommand.init);

configCmd
  .command('get <key>')
  .description('Get configuration value')
  .action(configCommand.get);

configCmd
  .command('set <key> <value>')
  .description('Set configuration value')
  .option('--secure', 'Store value securely in keychain')
  .action(configCommand.set);

configCmd
  .command('list')
  .alias('ls')
  .description('List all configuration values')
  .option('--show-secrets', 'Show secret values (use with caution)')
  .action(configCommand.list);

configCmd
  .command('reset')
  .description('Reset configuration to defaults')
  .option('--confirm', 'Skip confirmation prompt')
  .action(configCommand.reset);

// Additional utility commands
program
  .command('version')
  .alias('v')
  .description('Show version information')
  .action(() => {
    console.log(`A2A CLI v${program.version()}`);
    console.log('Agent-to-Agent DevOps Platform');
    console.log('Built with ❤️  for DevOps engineers');
  });

program
  .command('status')
  .description('Show system status and agent health')
  .option('--detailed', 'Show detailed status information')
  .option('--json', 'Output in JSON format')
  .option('--watch', 'Watch status changes in real-time')
  .option('--component <name>', 'Show status for specific component')
  .action(statusCommand);

// Cluster management commands
const clusterCmd = program
  .command('cluster')
  .description('Manage Kubernetes cluster connections and contexts');

clusterCmd
  .command('list')
  .alias('ls')
  .description('List available Kubernetes contexts')
  .action(() => clusterCommand({ list: true }));

clusterCmd
  .command('switch <context>')
  .description('Switch to a different Kubernetes context')
  .action((context) => clusterCommand({ switch: context }));

clusterCmd
  .command('info')
  .description('Show detailed cluster information')
  .action(() => clusterCommand({ info: true }));

clusterCmd
  .command('namespace <namespace>')
  .alias('ns')
  .description('Switch to a different namespace')
  .action((namespace) => clusterCommand({ namespace }));

// When no subcommand is provided, show current cluster info
clusterCmd
  .action(() => clusterCommand({}));

// Setup and configuration wizard
const setupCmd = program
  .command('setup')
  .description('Setup and configure A2A platform components');

setupCmd
  .command('guide')
  .description('Show platform-specific setup guide')
  .action(() => setupCommand({ guide: true }));

setupCmd
  .command('platform <platform>')
  .description('Setup for specific platform (aws-eks, gcp-gke, azure-aks, local)')
  .option('--auto', 'Auto-execute setup steps where possible')
  .action((platform, options) => setupCommand({ platform, auto: options.auto }));

setupCmd
  .command('component <component>')
  .description('Setup specific component (kubernetes, falco, prometheus, alertmanager)')
  .option('--auto', 'Auto-execute setup steps where possible')
  .action((component, options) => setupCommand({ component, auto: options.auto }));

// When no subcommand is provided, run interactive setup
setupCmd
  .action(() => setupCommand({}));

program
  .command('agents')
  .description('List available agents and their capabilities')
  .option('--detailed', 'Show detailed agent information')
  .action(async (options) => {
    const { agentsCommand } = await import('./commands/agents');
    await agentsCommand(options);
  });

// Security-focused commands
const securityCmd = program
  .command('security')
  .alias('sec')
  .description('Security-focused operations');

securityCmd
  .command('audit')
  .description('Run comprehensive security audit')
  .option('--namespace <name>', 'Kubernetes namespace to audit')
  .option('--export <format>', 'Export audit report (json, yaml, html, pdf)')
  .action(async (options) => {
    await queryCommand('run comprehensive security audit' + (options.namespace ? ` in ${options.namespace} namespace` : ''), {
      format: options.export || 'text',
      agent: 'falco'
    });
  });

securityCmd
  .command('threats')
  .description('Detect current security threats')
  .option('--time-range <range>', 'Time range to analyze (1h, 24h, 7d)', '1h')
  .option('--severity <level>', 'Minimum threat severity', 'medium')
  .action(async (options) => {
    await queryCommand(`detect security threats in last ${options.timeRange} with severity ${options.severity}`, {
      agent: 'falco'
    });
  });

securityCmd
  .command('score')
  .description('Calculate security posture score')
  .option('--baseline', 'Establish new security baseline')
  .action(async (options) => {
    await queryCommand('calculate security score' + (options.baseline ? ' and establish baseline' : ''), {
      agent: 'falco'
    });
  });

// Monitoring-focused commands  
const monitoringCmd = program
  .command('metrics')
  .alias('met')
  .description('Monitoring and metrics operations');

monitoringCmd
  .command('query <promql>')
  .description('Execute PromQL query')
  .option('--time-range <range>', 'Query time range', '5m')
  .option('--format <type>', 'Output format (table, json, csv)', 'table')
  .action(async (promql, options) => {
    await queryCommand(`execute prometheus query: ${promql} for time range ${options.timeRange}`, {
      format: options.format,
      agent: 'prometheus'
    });
  });

monitoringCmd
  .command('alerts')
  .description('Show active alerts')
  .option('--severity <level>', 'Filter by severity', 'all')
  .option('--state <state>', 'Filter by state (firing, pending)', 'all')
  .action(async (options) => {
    await queryCommand(`show active alerts with severity ${options.severity} and state ${options.state}`, {
      agent: 'prometheus'
    });
  });

monitoringCmd
  .command('health')
  .description('Show system health overview')
  .action(async () => {
    await queryCommand('show system health overview', {
      agent: 'prometheus'
    });
  });

// Help and documentation
program
  .command('docs')
  .description('Open documentation in browser')
  .option('--local', 'Open local documentation if available')
  .action(async (options) => {
    const { docsCommand } = await import('./commands/docs');
    await docsCommand(options);
  });

program
  .command('examples')
  .description('Show usage examples')
  .option('--category <cat>', 'Show examples for specific category (security, monitoring, general)')
  .action(async (options) => {
    const { examplesCommand } = await import('./commands/examples');
    await examplesCommand(options);
  });

// Error handling
program.configureOutput({
  writeErr: (str) => logger.error(str.trim()),
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection:', reason);
  process.exit(1);
});

// Handle interrupt signals gracefully
process.on('SIGINT', () => {
  logger.info('\\n👋 Goodbye! Thanks for using A2A CLI');
  process.exit(0);
});

process.on('SIGTERM', () => {
  logger.info('\\n🔄 A2A CLI terminated');
  process.exit(0);
});

// Parse command line arguments
if (require.main === module) {
  // Show help if no arguments provided
  if (process.argv.length <= 2) {
    program.help();
  } else {
    program.parse();
  }
}

export { program };