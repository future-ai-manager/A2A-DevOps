#!/usr/bin/env node

const { spawn, exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const path = require('path');

const execAsync = promisify(exec);

// Color functions
const colors = {
  red: text => `\x1b[31m${text}\x1b[0m`,
  green: text => `\x1b[32m${text}\x1b[0m`,
  yellow: text => `\x1b[33m${text}\x1b[0m`,
  blue: text => `\x1b[34m${text}\x1b[0m`,
  cyan: text => `\x1b[36m${text}\x1b[0m`,
  gray: text => `\x1b[90m${text}\x1b[0m`
};

const checks = [
  {
    name: 'Node.js',
    command: 'node --version',
    validator: (output) => {
      const version = output.trim().replace('v', '');
      const majorVersion = parseInt(version.split('.')[0]);
      return { 
        valid: majorVersion >= 18, 
        message: majorVersion >= 18 ? `${output.trim()} (✓ compatible)` : `${output.trim()} (requires v18.0.0+)`
      };
    },
    required: true
  },
  {
    name: 'Claude Code',
    command: 'claude --version',
    validator: (output) => ({ valid: true, message: `${output.trim()} (installed)` }),
    required: true,
    postCheck: async () => {
      try {
        await execAsync('claude auth whoami');
        return { authenticated: true, message: 'authenticated' };
      } catch {
        return { authenticated: false, message: 'not authenticated - run: claude auth login' };
      }
    }
  },
  {
    name: 'Falco',
    command: 'falco --version',
    validator: (output) => ({ valid: true, message: `${output.trim()} (available)` }),
    required: false,
    postCheck: async () => {
      try {
        await execAsync('systemctl is-active falco');
        return { running: true, message: 'running as service' };
      } catch {
        try {
          const { stdout } = await execAsync('docker ps --filter name=falco --quiet');
          if (stdout.trim()) {
            return { running: true, message: 'running in Docker' };
          } else {
            return { running: false, message: 'not running - start with: sudo systemctl start falco' };
          }
        } catch {
          return { running: false, message: 'status unknown' };
        }
      }
    }
  },
  {
    name: 'Prometheus',
    command: 'prometheus --version',
    validator: (output) => ({ valid: true, message: `${output.trim().split('\\n')[0]} (installed)` }),
    required: false,
    postCheck: async () => {
      try {
        const axios = require('axios');
        await axios.get('http://localhost:9090/-/healthy', { timeout: 3000 });
        return { accessible: true, message: 'accessible at :9090' };
      } catch {
        return { accessible: false, message: 'not accessible at :9090' };
      }
    }
  },
  {
    name: 'Docker',
    command: 'docker --version',
    validator: (output) => ({ valid: true, message: `${output.trim()} (available)` }),
    required: false,
    postCheck: async () => {
      try {
        await execAsync('docker ps');
        return { running: true, message: 'daemon running' };
      } catch {
        return { running: false, message: 'daemon not accessible' };
      }
    }
  },
  {
    name: 'kubectl',
    command: 'kubectl version --client --short',
    validator: (output) => ({ valid: true, message: `${output.trim()} (available)` }),
    required: false,
    postCheck: async () => {
      try {
        const { stdout } = await execAsync('kubectl cluster-info');
        if (stdout.includes('running at')) {
          return { connected: true, message: 'cluster connected' };
        } else {
          return { connected: false, message: 'no cluster connection' };
        }
      } catch {
        return { connected: false, message: 'no cluster connection' };
      }
    }
  }
];

async function runCheck(check) {
  console.log(colors.blue(`Checking ${check.name}...`));
  
  try {
    const { stdout, stderr } = await execAsync(check.command);
    const output = stdout || stderr;
    
    const validation = check.validator(output);
    
    if (validation.valid) {
      console.log(colors.green(`  ✓ ${check.name}: ${validation.message}`));
    } else {
      console.log(colors.red(`  ✗ ${check.name}: ${validation.message}`));
    }
    
    // Run post-check if available
    if (check.postCheck) {
      try {
        const postResult = await check.postCheck();
        const statusKeys = Object.keys(postResult).filter(key => key !== 'message');
        if (statusKeys.length > 0) {
          const status = postResult[statusKeys[0]];
          const color = status ? colors.green : colors.yellow;
          console.log(color(`    ${postResult.message}`));
        }
      } catch (postError) {
        console.log(colors.yellow(`    post-check failed: ${postError.message}`));
      }
    }
    
    return { ...validation, available: true };
    
  } catch (error) {
    if (check.required) {
      console.log(colors.red(`  ✗ ${check.name}: not installed or not in PATH`));
    } else {
      console.log(colors.yellow(`  ⚠ ${check.name}: not installed (optional)`));
    }
    return { valid: false, available: false, required: check.required };
  }
}

async function checkDependencies() {
  console.log(colors.cyan('🔍 A2A Dependency Checker'));
  console.log(colors.cyan('=' .repeat(40)));
  console.log('');
  
  const results = [];
  
  // Run all checks
  for (const check of checks) {
    const result = await runCheck(check);
    results.push({ name: check.name, ...result, required: check.required });
    console.log(''); // Empty line after each check
  }
  
  // Summary
  console.log(colors.cyan('📊 Summary'));
  console.log(colors.cyan('-'.repeat(20)));
  
  const available = results.filter(r => r.available).length;
  const missing = results.filter(r => !r.available).length;
  const requiredMissing = results.filter(r => r.required && !r.available).length;
  
  console.log(`Available: ${colors.green(available)}`);
  console.log(`Missing: ${colors.yellow(missing)}`);
  console.log(`Required missing: ${colors.red(requiredMissing)}`);
  console.log('');
  
  // Recommendations
  console.log(colors.cyan('💡 Recommendations'));
  console.log(colors.cyan('-'.repeat(25)));
  
  if (requiredMissing > 0) {
    console.log(colors.red('❌ Critical dependencies missing:'));
    results.filter(r => r.required && !r.available).forEach(r => {
      console.log(colors.red(`  • Install ${r.name}`));
    });
    console.log('');
  }
  
  const optionalMissing = results.filter(r => !r.required && !r.available);
  if (optionalMissing.length > 0) {
    console.log(colors.yellow('⚠️ Optional dependencies missing:'));
    optionalMissing.forEach(r => {
      console.log(colors.yellow(`  • ${r.name} - for enhanced functionality`));
    });
    console.log('');
  }
  
  // Installation suggestions
  if (requiredMissing > 0 || optionalMissing.length > 0) {
    console.log(colors.cyan('📦 Installation Suggestions'));
    console.log(colors.cyan('-'.repeat(30)));
    
    const missingTools = results.filter(r => !r.available);
    
    missingTools.forEach(tool => {
      switch (tool.name) {
        case 'Claude Code':
          console.log(colors.gray('  Claude Code: npm install -g @anthropic/claude-code'));
          console.log(colors.gray('  Then authenticate: claude auth login'));
          break;
        case 'Falco':
          console.log(colors.gray('  Falco: https://falco.org/docs/getting-started/installation/'));
          break;
        case 'Prometheus':
          console.log(colors.gray('  Prometheus: https://prometheus.io/download/'));
          break;
        case 'Docker':
          console.log(colors.gray('  Docker: https://docs.docker.com/get-docker/'));
          break;
        case 'kubectl':
          console.log(colors.gray('  kubectl: https://kubernetes.io/docs/tasks/tools/'));
          break;
      }
    });
    console.log('');
  }
  
  // Next steps
  if (requiredMissing === 0) {
    console.log(colors.green('🎉 All required dependencies are available!'));
    console.log(colors.green('You can now run: a2a query "your question here"'));
  } else {
    console.log(colors.red('🚫 Please install required dependencies before using A2A'));
  }
  
  console.log('');
  console.log(colors.gray('For more help, run: a2a doctor'));
  
  // Create setup status file
  await createSetupStatus(results);
  
  // Exit with appropriate code
  process.exit(requiredMissing > 0 ? 1 : 0);
}

async function createSetupStatus(results) {
  try {
    const homeDir = process.env.HOME || process.env.USERPROFILE || process.cwd();
    const a2aDir = path.join(homeDir, '.a2a');
    const statusFile = path.join(a2aDir, 'setup-status.json');
    
    // Ensure directory exists
    if (!fs.existsSync(a2aDir)) {
      fs.mkdirSync(a2aDir, { recursive: true });
    }
    
    const status = {
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      dependencies: results.map(r => ({
        name: r.name,
        available: r.available,
        required: r.required,
        valid: r.valid
      })),
      ready: results.filter(r => r.required && !r.available).length === 0
    };
    
    fs.writeFileSync(statusFile, JSON.stringify(status, null, 2));
    console.log(colors.gray(`Setup status saved to: ${statusFile}`));
    
  } catch (error) {
    console.log(colors.yellow(`Warning: Could not save setup status: ${error.message}`));
  }
}

// Handle errors
process.on('uncaughtException', (error) => {
  console.log(colors.red('\\n❌ Unexpected error during dependency check:'));
  console.log(colors.red(error.message));
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.log(colors.red('\\n❌ Unhandled rejection during dependency check:'));
  console.log(colors.red(reason));
  process.exit(1);
});

// Run the check if this script is executed directly
if (require.main === module) {
  checkDependencies().catch(error => {
    console.log(colors.red('\\n❌ Dependency check failed:'));
    console.log(colors.red(error.message));
    process.exit(1);
  });
}

module.exports = { checkDependencies, runCheck, checks };