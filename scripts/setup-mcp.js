#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const writeFile = promisify(fs.writeFile);
const mkdir = promisify(fs.mkdir);

// Color functions
const colors = {
  red: text => `\x1b[31m${text}\x1b[0m`,
  green: text => `\x1b[32m${text}\x1b[0m`,
  yellow: text => `\x1b[33m${text}\x1b[0m`,
  blue: text => `\x1b[34m${text}\x1b[0m`,
  cyan: text => `\x1b[36m${text}\x1b[0m`,
  gray: text => `\x1b[90m${text}\x1b[0m`
};

const DEFAULT_MCP_SERVERS = {
  servers: [
    {
      name: "falco",
      description: "Falco Security Agent for runtime security monitoring",
      command: "a2a-falco-mcp-server",
      args: ["--port", "3001"],
      env: {},
      capabilities: [
        "security-monitoring",
        "threat-detection",
        "container-security",
        "compliance-checking"
      ],
      domain: "security",
      priority: 1,
      autoStart: true,
      healthCheck: {
        enabled: true,
        interval: 30000,
        timeout: 5000,
        endpoint: "/health"
      }
    },
    {
      name: "prometheus", 
      description: "Prometheus Monitoring Agent for metrics collection",
      command: "a2a-prometheus-mcp-server",
      args: ["--port", "3002"],
      env: {
        "PROMETHEUS_URL": "http://localhost:9090"
      },
      capabilities: [
        "metrics-collection",
        "performance-monitoring", 
        "alerting",
        "time-series-analysis"
      ],
      domain: "monitoring",
      priority: 1,
      autoStart: true,
      healthCheck: {
        enabled: true,
        interval: 30000,
        timeout: 5000,
        endpoint: "/health"
      }
    }
  ],
  settings: {
    maxConcurrentServers: 10,
    startupTimeout: 30000,
    shutdownTimeout: 10000,
    healthCheckInterval: 30000,
    logLevel: "info",
    enableMetrics: true,
    metricsPort: 9091
  }
};

const DEFAULT_FALCO_RULES = `# A2A Falco Rules Configuration
# This file contains Falco rules specifically for A2A DevOps monitoring

# Metadata
- required_engine_version: 0.35.0

# Macros
- macro: a2a_containers
  condition: container and not container.image.repository in (falco, prometheus, node_exporter)

- macro: sensitive_files
  condition: >
    fd.name startswith /etc or
    fd.name startswith /usr/bin or
    fd.name startswith /usr/sbin or
    fd.name startswith /sbin

# Rules for A2A monitoring
- rule: A2A Unauthorized File Access
  desc: Detect unauthorized access to sensitive files in A2A monitored containers
  condition: >
    a2a_containers and
    open_read and
    sensitive_files and
    not proc.name in (cat, ls, find, grep, tail, head)
  output: >
    Unauthorized file access in A2A container
    (user=%user.name command=%proc.cmdline file=%fd.name 
    container_id=%container.id container_name=%container.name)
  priority: HIGH
  tags: [filesystem, security, a2a]

- rule: A2A Container Shell Access
  desc: Detect shell access in A2A monitored containers
  condition: >
    a2a_containers and
    spawned_process and
    shell_procs
  output: >
    Shell spawned in A2A container
    (user=%user.name shell=%proc.name container_id=%container.id 
    container_name=%container.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
  tags: [shell, container, a2a]

- rule: A2A Privilege Escalation
  desc: Detect privilege escalation attempts in A2A environment
  condition: >
    a2a_containers and
    spawned_process and
    (proc.name in (sudo, su, runuser) or 
     (proc.name=passwd and proc.args contains root))
  output: >
    Privilege escalation attempt in A2A environment
    (user=%user.name command=%proc.cmdline container_id=%container.id)
  priority: CRITICAL
  tags: [privilege, escalation, a2a]

- rule: A2A Network Anomaly
  desc: Detect unusual network activity in A2A containers
  condition: >
    a2a_containers and
    (inbound_outbound) and
    fd.sport > 32768 and
    not fd.sport in (prometheus_ports)
  output: >
    Unusual network activity in A2A container
    (connection=%fd.name container=%container.name 
    sport=%fd.sport dport=%fd.dport)
  priority: MEDIUM  
  tags: [network, anomaly, a2a]

# Exceptions for known A2A processes
- list: a2a_allowed_processes
  items: [node, npm, falco, prometheus, kubectl, docker]

- macro: a2a_legitimate_activity
  condition: proc.name in (a2a_allowed_processes)

# Override some default rules for A2A context
- rule: Terminal shell in container
  condition: >
    spawned_process and container and shell_procs and proc.tty != 0 
    and container_entrypoint and not a2a_legitimate_activity
  append: false`;

async function setupMCP() {
  console.log(colors.cyan('🔧 A2A MCP Server Setup'));
  console.log(colors.cyan('=' .repeat(30)));
  console.log('');

  try {
    // Determine configuration directories
    const homeDir = process.env.HOME || process.env.USERPROFILE || process.cwd();
    const a2aDir = path.join(homeDir, '.a2a');
    const configDir = path.join(a2aDir, 'config');
    const logsDir = path.join(a2aDir, 'logs');
    const cacheDir = path.join(a2aDir, 'cache');

    console.log(colors.blue('Creating A2A directories...'));
    
    // Create directories
    await ensureDirectory(a2aDir);
    await ensureDirectory(configDir);
    await ensureDirectory(logsDir);
    await ensureDirectory(cacheDir);
    
    console.log(colors.green(`✓ Created: ${a2aDir}`));
    console.log(colors.green(`✓ Created: ${configDir}`));
    console.log(colors.green(`✓ Created: ${logsDir}`));
    console.log(colors.green(`✓ Created: ${cacheDir}`));
    console.log('');

    // Create MCP servers configuration
    console.log(colors.blue('Setting up MCP server configuration...'));
    const mcpConfigPath = path.join(configDir, 'mcp-servers.json');
    await writeFile(mcpConfigPath, JSON.stringify(DEFAULT_MCP_SERVERS, null, 2));
    console.log(colors.green(`✓ Created: ${mcpConfigPath}`));

    // Create Falco rules configuration
    console.log(colors.blue('Setting up Falco rules...'));
    const falcoRulesPath = path.join(configDir, 'falco-rules.yaml');
    await writeFile(falcoRulesPath, DEFAULT_FALCO_RULES);
    console.log(colors.green(`✓ Created: ${falcoRulesPath}`));

    // Create default A2A configuration
    console.log(colors.blue('Setting up A2A configuration...'));
    const a2aConfig = {
      version: "1.0.0",
      claudeCode: {
        timeout: 30000,
        maxRetries: 3
      },
      monitoring: {
        prometheusUrl: "http://localhost:9090",
        falcoSocket: "/var/run/falco.sock",
        falcoRulesPath: falcoRulesPath
      },
      notifications: {
        slack: {
          enabled: false,
          webhookUrl: ""
        },
        pagerduty: {
          enabled: false,
          apiKey: ""
        }
      },
      mcp: {
        serversConfigPath: mcpConfigPath,
        maxConcurrentServers: 10,
        healthCheckInterval: 30000
      },
      debug: false,
      logLevel: "info"
    };

    const a2aConfigPath = path.join(configDir, 'config.json');
    await writeFile(a2aConfigPath, JSON.stringify(a2aConfig, null, 2));
    console.log(colors.green(`✓ Created: ${a2aConfigPath}`));
    console.log('');

    // Create environment file template
    console.log(colors.blue('Creating environment template...'));
    const envTemplate = `# A2A Environment Configuration
# Copy this to .env and customize as needed

# Claude Code Configuration
A2A_CLAUDE_TIMEOUT=30000
A2A_CLAUDE_MAX_RETRIES=3

# Monitoring Configuration
A2A_PROMETHEUS_URL=http://localhost:9090
A2A_FALCO_SOCKET=/var/run/falco.sock

# Notification Configuration (optional)
# A2A_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
# A2A_PAGERDUTY_API_KEY=your-pagerduty-api-key

# Debug and Logging
A2A_DEBUG=false
A2A_LOG_LEVEL=info
A2A_LOG_DIR=${logsDir}

# Web UI Configuration
A2A_WEB_PORT=3000
A2A_WEB_HOST=localhost

# MCP Configuration
A2A_MCP_CONFIG_PATH=${mcpConfigPath}
A2A_MAX_CONCURRENT_SERVERS=10
`;

    const envPath = path.join(a2aDir, 'env.template');
    await writeFile(envPath, envTemplate);
    console.log(colors.green(`✓ Created: ${envPath}`));
    console.log('');

    // Create systemd service file template
    console.log(colors.blue('Creating systemd service template...'));
    const serviceTemplate = `[Unit]
Description=A2A DevOps Platform
After=network.target

[Service]
Type=simple
User=a2a
Group=a2a
WorkingDirectory=${a2aDir}
Environment=NODE_ENV=production
Environment=A2A_CONFIG_DIR=${configDir}
ExecStart=/usr/bin/node ${path.resolve(__dirname, '../dist/cli/index.js')} serve --daemon
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${a2aDir}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=a2a

[Install]
WantedBy=multi-user.target
`;

    const servicePath = path.join(configDir, 'a2a.service');
    await writeFile(servicePath, serviceTemplate);
    console.log(colors.green(`✓ Created: ${servicePath}`));
    console.log('');

    // Create Docker Compose template for development
    console.log(colors.blue('Creating Docker Compose template...'));
    const dockerComposeTemplate = `version: '3.8'

services:
  falco:
    image: falcosecurity/falco:latest
    container_name: a2a-falco
    privileged: true
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - /dev:/host/dev
      - /proc:/host/proc:ro
      - /boot:/host/boot:ro
      - /lib/modules:/host/lib/modules:ro
      - /usr:/host/usr:ro
      - /etc:/host/etc:ro
      - ${configDir}/falco-rules.yaml:/etc/falco/falco_rules.local.yaml:ro
    command:
      - /usr/bin/falco
      - --cri
      - /host/var/run/docker.sock
      - -K
      - /var/run/secrets/kubernetes.io/serviceaccount/token
      - -k
      - https://kubernetes.default
      - -pk
    networks:
      - a2a-network

  prometheus:
    image: prom/prometheus:latest
    container_name: a2a-prometheus
    ports:
      - "9090:9090"
    volumes:
      - prometheus-data:/prometheus
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--web.enable-lifecycle'
    networks:
      - a2a-network

  a2a-web:
    build: .
    container_name: a2a-web
    ports:
      - "3000:3000"
    volumes:
      - ${a2aDir}:/app/.a2a:ro
    environment:
      - NODE_ENV=production
      - A2A_CONFIG_DIR=/app/.a2a/config
      - A2A_PROMETHEUS_URL=http://prometheus:9090
      - A2A_FALCO_SOCKET=/var/run/falco.sock
    depends_on:
      - falco
      - prometheus
    networks:
      - a2a-network

volumes:
  prometheus-data:

networks:
  a2a-network:
    driver: bridge
`;

    const dockerComposePath = path.join(configDir, 'docker-compose.yml');
    await writeFile(dockerComposePath, dockerComposeTemplate);
    console.log(colors.green(`✓ Created: ${dockerComposePath}`));
    console.log('');

    // Create installation verification script
    console.log(colors.blue('Creating verification script...'));
    const verificationScript = `#!/bin/bash
# A2A Installation Verification Script

echo "🔍 A2A Installation Verification"
echo "================================"
echo ""

# Check if A2A is installed
if command -v a2a &> /dev/null; then
    echo "✓ A2A CLI is installed"
    a2a --version
else
    echo "✗ A2A CLI not found in PATH"
    exit 1
fi

echo ""

# Check configuration directory
if [ -d "${a2aDir}" ]; then
    echo "✓ A2A configuration directory exists: ${a2aDir}"
else
    echo "✗ A2A configuration directory missing: ${a2aDir}"
    exit 1
fi

echo ""

# Run dependency check
echo "Running dependency check..."
a2a doctor

echo ""
echo "🎉 A2A installation verification complete!"
echo ""
echo "Next steps:"
echo "  1. Run 'a2a config init' to initialize configuration"
echo "  2. Run 'a2a query \"hello world\"' to test the system"
echo "  3. Visit the documentation for more information"
`;

    const verificationPath = path.join(configDir, 'verify-installation.sh');
    await writeFile(verificationPath, verificationScript);
    
    // Make script executable (Unix-like systems)
    if (process.platform !== 'win32') {
      try {
        const { exec } = require('child_process');
        const { promisify } = require('util');
        const execAsync = promisify(exec);
        await execAsync(`chmod +x ${verificationPath}`);
      } catch (error) {
        console.log(colors.yellow(`Warning: Could not make verification script executable: ${error.message}`));
      }
    }
    
    console.log(colors.green(`✓ Created: ${verificationPath}`));
    console.log('');

    // Final summary
    console.log(colors.green('🎉 MCP Setup Complete!'));
    console.log(colors.green('=' .repeat(25)));
    console.log('');
    console.log(colors.cyan('📁 Configuration Files Created:'));
    console.log(colors.gray(`  ${mcpConfigPath}`));
    console.log(colors.gray(`  ${falcoRulesPath}`));
    console.log(colors.gray(`  ${a2aConfigPath}`));
    console.log(colors.gray(`  ${envPath}`));
    console.log(colors.gray(`  ${servicePath}`));
    console.log(colors.gray(`  ${dockerComposePath}`));
    console.log(colors.gray(`  ${verificationPath}`));
    console.log('');
    
    console.log(colors.cyan('🚀 Next Steps:'));
    console.log('  1. Run: a2a config init');
    console.log('  2. Run: a2a doctor (to check dependencies)');
    console.log('  3. Test with: a2a query "hello world"');
    console.log('  4. Start monitoring: a2a monitor');
    console.log('  5. Launch web UI: a2a serve');
    console.log('');
    
    console.log(colors.cyan('📖 Documentation:'));
    console.log(colors.gray('  Use environment template: cp ~/.a2a/env.template ~/.a2a/.env'));
    console.log(colors.gray('  For Docker setup: cd ~/.a2a/config && docker-compose up'));
    console.log(colors.gray('  For systemd service: sudo cp ~/.a2a/config/a2a.service /etc/systemd/system/'));
    console.log('');

  } catch (error) {
    console.log(colors.red('❌ MCP setup failed:'));
    console.log(colors.red(error.message));
    console.log('');
    console.log(colors.yellow('Please check permissions and try again.'));
    process.exit(1);
  }
}

async function ensureDirectory(dirPath) {
  try {
    if (!fs.existsSync(dirPath)) {
      await mkdir(dirPath, { recursive: true });
    }
  } catch (error) {
    throw new Error(`Failed to create directory ${dirPath}: ${error.message}`);
  }
}

// Run setup if this script is executed directly
if (require.main === module) {
  setupMCP().catch(error => {
    console.log(colors.red('\\n❌ Setup failed:'));
    console.log(colors.red(error.message));
    process.exit(1);
  });
}

module.exports = { setupMCP, DEFAULT_MCP_SERVERS, DEFAULT_FALCO_RULES };