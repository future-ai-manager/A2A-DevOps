# Quick Start Guide - A2A CLI

## Prerequisites

Before installing A2A CLI, ensure you have the following installed:

1. **Node.js** (v18.0 or higher)
   ```bash
   node --version  # Should output v18.0.0 or higher
   ```

2. **Claude Code** (authenticated)
   ```bash
   claude --version
   # If not installed, visit: https://docs.anthropic.com/claude-code
   ```

3. **Falco** (for security features)
   ```bash
   sudo falco --version
   # Installation: https://falco.org/docs/getting-started/installation/
   ```

4. **Kubernetes** access (kubectl configured)
   ```bash
   kubectl cluster-info
   ```

## Installation

### Method 1: NPM Global Installation (Recommended)

```bash
# Install globally
npm install -g @devops/a2a-cli

# Verify installation
a2a --version
```

### Method 2: Local Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/a2a-cli.git
cd a2a-cli

# Install dependencies
npm install

# Build the project
npm run build

# Link for global usage
npm link

# Verify
a2a --version
```

## Initial Setup

### Step 1: Check Dependencies

Run the doctor command to verify all dependencies are properly installed:

```bash
a2a doctor
```

Expected output:
```
Checking dependencies...
✓ Node.js v20.0.0
✓ Claude Code v1.0.0 (authenticated)
✓ Falco v0.35.0
✓ Kubernetes cluster accessible
✓ Prometheus endpoint reachable

All systems operational!
```

### Step 2: Configure A2A

Initialize configuration:

```bash
a2a config init
```

This creates `~/.a2a/config.json` with default settings:

```json
{
  "claudeCode": {
    "timeout": 30000,
    "maxRetries": 3
  },
  "monitoring": {
    "prometheusUrl": "http://localhost:9090",
    "falcoSocket": "/var/run/falco.sock"
  },
  "notifications": {
    "slack": {
      "enabled": false,
      "webhookUrl": ""
    }
  }
}
```

### Step 3: Test Basic Functionality

Run a simple query to verify everything works:

```bash
a2a query "What security tools are available?"
```

Expected response:
```
Available security agents:
- Falco: Runtime security monitoring
- Trivy: Container vulnerability scanning (planned)
- Kubescape: Security posture management (planned)
```

## Basic Usage

### Natural Language Queries

Process any DevOps-related query:

```bash
# Security check
a2a query "Check for security threats in the last hour"

# Monitoring query
a2a query "Show CPU usage for all pods in default namespace"

# General question
a2a query "What's the best practice for container security?"
```

### Direct Commands

Use specific commands for common operations:

```bash
# Start real-time monitoring
a2a monitor --severity high

# Run security audit
a2a audit --namespace production

# Check specific container
a2a check container nginx-deployment-7cd9bf6b4-x2p5q
```

### Output Formats

Control output format for scripting:

```bash
# JSON output
a2a query "list all security events" --format json

# YAML output
a2a query "get cluster metrics" --format yaml

# Plain text (default)
a2a query "check system status"
```

## Advanced Features

### Real-time Monitoring

Start background monitoring with alerts:

```bash
# Monitor with console output
a2a monitor

# Monitor with Slack notifications
a2a monitor --notify slack

# Monitor specific namespace
a2a monitor --namespace production --severity critical
```

### Web UI (Optional)

Launch the web interface for visualization:

```bash
# Start web UI on default port (3000)
a2a serve

# Custom port
a2a serve --port 8080

# With API only (no UI)
a2a serve --api-only
```

Access the UI at `http://localhost:3000`

### Scripting and Automation

Use A2A in scripts and CI/CD pipelines:

```bash
#!/bin/bash
# security-check.sh

# Run security audit
result=$(a2a query "check security compliance" --format json)

# Parse result
score=$(echo $result | jq '.security_score')

# Exit based on score
if [ $score -lt 80 ]; then
  echo "Security score too low: $score"
  exit 1
fi

echo "Security check passed: $score"
```

### Pipeline Integration

```yaml
# .github/workflows/security.yml
name: Security Check
on: [push]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '18'
      
      - name: Install A2A CLI
        run: npm install -g @devops/a2a-cli
      
      - name: Run Security Audit
        run: a2a audit --format json > security-report.json
      
      - name: Check Security Score
        run: |
          score=$(cat security-report.json | jq '.score')
          if [ $score -lt 80 ]; then exit 1; fi
```

## Configuration

### Environment Variables

Override configuration with environment variables:

```bash
# Set Prometheus URL
export A2A_PROMETHEUS_URL=http://prometheus.example.com:9090

# Enable debug mode
export A2A_DEBUG=true

# Set log level
export A2A_LOG_LEVEL=debug

# Dry run mode (no actual operations)
export A2A_DRY_RUN=true
```

### Custom MCP Servers

Add custom MCP servers by editing `~/.a2a/mcp-servers.json`:

```json
{
  "servers": [
    {
      "name": "custom-tool",
      "command": "custom-mcp-server",
      "args": ["--port", "5000"],
      "domain": "monitoring"
    }
  ]
}
```

### Notification Setup

#### Slack Integration

1. Create Slack webhook: https://api.slack.com/messaging/webhooks
2. Update configuration:

```bash
a2a config set notifications.slack.webhookUrl "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
a2a config set notifications.slack.enabled true
```

#### PagerDuty Integration

```bash
a2a config set notifications.pagerduty.apiKey "YOUR-API-KEY"
a2a config set notifications.pagerduty.enabled true
```

## Updating

### Update to Latest Version

```bash
# Check current version
a2a --version

# Update via npm
npm update -g @devops/a2a-cli

# Verify update
a2a --version
```

### Migration Between Versions

When updating between major versions:

```bash
# Backup configuration
cp -r ~/.a2a ~/.a2a.backup

# Update
npm update -g @devops/a2a-cli

# Run migration
a2a migrate
```

## Troubleshooting

### Common Issues

#### Issue: Claude Code not found

```bash
Error: Claude Code CLI not found in PATH
```

**Solution:**
```bash
# Install Claude Code
npm install -g @anthropic/claude-code

# Authenticate
claude auth login
```

#### Issue: Falco permission denied

```bash
Error: Cannot access Falco socket: Permission denied
```

**Solution:**
```bash
# Add user to falco group
sudo usermod -a -G falco $USER

# Restart session
logout
```

#### Issue: Prometheus connection refused

```bash
Error: Cannot connect to Prometheus at localhost:9090
```

**Solution:**
```bash
# Update Prometheus URL
a2a config set monitoring.prometheusUrl "http://your-prometheus:9090"
```

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
# Maximum verbosity
A2A_DEBUG=* a2a query "test query"

# Specific module debugging
A2A_DEBUG=a2a:claude a2a query "test query"

# Log to file
A2A_DEBUG=* a2a query "test query" 2> debug.log
```

### Getting Help

```bash
# General help
a2a --help

# Command-specific help
a2a query --help
a2a monitor --help

# Check documentation
a2a docs

# Report issues
a2a feedback
```

## Performance Tips

### Query Optimization

1. **Use specific queries**: More specific queries route faster
   ```bash
   # Good
   a2a query "check nginx pod security in production namespace"
   
   # Less optimal
   a2a query "check security"
   ```

2. **Cache frequent queries**: Results are cached for 5 minutes
   ```bash
   # First query (slower)
   a2a query "get all metrics" --cache
   
   # Subsequent queries (instant)
   a2a query "get all metrics" --cache
   ```

3. **Batch operations**: Combine related queries
   ```bash
   # Instead of multiple queries
   a2a query "check security and get metrics for production"
   ```

### Resource Management

Monitor A2A resource usage:

```bash
# Check resource usage
a2a stats

# Limit memory usage
export A2A_MAX_MEMORY=512

# Limit concurrent operations
export A2A_MAX_CONCURRENT=2
```

## Security Best Practices

### Credential Management

1. **Never commit credentials**
   ```bash
   # Use environment variables
   export SLACK_WEBHOOK_URL="your-url"
   a2a config set notifications.slack.webhookUrl "$SLACK_WEBHOOK_URL"
   ```

2. **Use secure storage**
   ```bash
   # Store in system keychain (when available)
   a2a config set --secure api.keys.prometheus "your-api-key"
   ```

3. **Rotate credentials regularly**
   ```bash
   # Update credentials
   a2a config rotate-keys
   ```

### Audit Logging

Enable audit logging for compliance:

```bash
# Enable audit log
a2a config set audit.enabled true
a2a config set audit.path "/var/log/a2a/audit.log"

# View audit log
a2a audit-log view --last 100
```

## Examples

### Complete Security Audit

```bash
#!/bin/bash
# comprehensive-audit.sh

echo "Starting comprehensive security audit..."

# Check runtime threats
echo "Checking runtime threats..."
a2a query "detect runtime threats in last 24 hours" --format json > runtime-threats.json

# Check container vulnerabilities
echo "Scanning container images..."
a2a query "scan all container images for vulnerabilities" --format json > vulnerabilities.json

# Check compliance
echo "Evaluating compliance..."
a2a query "check CIS benchmark compliance" --format json > compliance.json

# Generate report
echo "Generating report..."
a2a report generate \
  --runtime runtime-threats.json \
  --vulnerabilities vulnerabilities.json \
  --compliance compliance.json \
  --output security-report.html

echo "Audit complete. Report saved to security-report.html"
```

### Continuous Monitoring Setup

```bash
#!/bin/bash
# setup-monitoring.sh

# Configure monitoring
a2a config set monitoring.enabled true
a2a config set monitoring.interval 60
a2a config set monitoring.severity "high,critical"

# Setup notifications
a2a config set notifications.slack.enabled true
a2a config set notifications.slack.channel "#security-alerts"

# Start monitoring daemon
a2a monitor --daemon --pid-file /var/run/a2a-monitor.pid

echo "Monitoring setup complete"
```

## Support

### Documentation
- Full documentation: https://docs.a2a-cli.dev