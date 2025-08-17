import { MCPServerManager } from '@core/MCPServerManager';
import { Logger } from '../utils/logger';
import chalk from 'chalk';
import ora from 'ora';
import { existsSync } from 'fs';
import path from 'path';

const logger = Logger.getInstance();

export interface ValidateOptions {
  categories?: string[];
  mode?: string;
  timeout?: string;
  parallel?: boolean;
  report?: boolean;
  output?: string;
  verbose?: boolean;
}

export async function validateCommand(options: ValidateOptions): Promise<void> {
  const spinner = ora('Initializing security validation...').start();

  try {
    const {
      categories = ['filesystem', 'process', 'network', 'privilege', 'container', 'kubernetes'],
      mode = 'safe',
      timeout = '30000',
      parallel = false,
      report = true,
      output = './security-validation-logs',
      verbose = false
    } = options;

    // Initialize MCP Server Manager
    spinner.text = 'Starting MCP servers...';
    const serverManager = new MCPServerManager();
    await serverManager.start();

    // Get Falco server
    const falcoServer = serverManager.getServer('falco');
    if (!falcoServer) {
      spinner.fail('Falco server not available');
      logger.errorMessage('Falco security server is required for validation');
      process.exit(1);
    }

    spinner.succeed('Security validation initialized');

    // Display validation parameters
    console.log(chalk.blue('🔍 Security Checklist Validation'));
    console.log(chalk.blue('=' .repeat(40)));
    console.log(chalk.gray(`Categories: ${categories.join(', ')}`));
    console.log(chalk.gray(`Mode: ${mode}`));
    console.log(chalk.gray(`Timeout: ${timeout}ms per test`));
    console.log(chalk.gray(`Parallel execution: ${parallel ? 'enabled' : 'disabled'}`));
    console.log(chalk.gray(`Generate report: ${report ? 'yes' : 'no'}`));
    console.log('');

    // Show warning for aggressive mode
    if (mode === 'aggressive') {
      console.log(chalk.red('⚠️  WARNING: Aggressive mode will execute actual security tests'));
      console.log(chalk.red('   This may trigger real security alerts and events!'));
      console.log('');
      
      // Add confirmation for aggressive mode
      const { confirmAggressive } = await require('inquirer').prompt([
        {
          type: 'confirm',
          name: 'confirmAggressive',
          message: 'Are you sure you want to run in aggressive mode?',
          default: false
        }
      ]);

      if (!confirmAggressive) {
        console.log(chalk.yellow('Validation cancelled by user'));
        return;
      }
      console.log('');
    }

    // Execute validation
    const validationSpinner = ora('Executing security checklist validation...').start();

    try {
      const result = await falcoServer.handleToolCall('security_test_validation', {
        categories,
        testMode: mode,
        timeout: parseInt(timeout),
        parallel,
        generateReport: report,
        logLevel: verbose ? 'debug' : 'info',
        outputDir: output
      });

      if (!result.success) {
        validationSpinner.fail('Security validation failed');
        logger.errorMessage(result.error || 'Unknown validation error');
        process.exit(1);
      }

      validationSpinner.succeed('Security validation completed');

      // Display results
      await displayValidationResults(result.data);

      // Show log location
      if (existsSync(output)) {
        console.log(chalk.blue('\n📁 Validation Logs and Reports:'));
        console.log(chalk.gray(`   ${path.resolve(output)}`));
        
        // List generated files
        const sessionDir = path.join(output, result.data.sessionId);
        if (existsSync(sessionDir)) {
          console.log(chalk.gray(`   Session directory: ${sessionDir}`));
        }
      }

    } catch (error) {
      validationSpinner.fail('Validation execution failed');
      throw error;
    }

    // Cleanup
    await serverManager.stop();

  } catch (error) {
    spinner.fail('Security validation failed');
    logger.errorMessage(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    
    // Provide helpful suggestions
    if (error instanceof Error) {
      if (error.message.includes('Falco')) {
        console.log(chalk.yellow('💡 Make sure Falco is installed and running'));
        console.log(chalk.gray('   Install: https://falco.org/docs/getting-started/installation/'));
        console.log(chalk.gray('   Check status: sudo systemctl status falco'));
      }
    }
    
    process.exit(1);
  }
}

async function displayValidationResults(data: any): Promise<void> {
  const { validationReport, recommendations, nextSteps } = data;

  console.log('\n' + chalk.blue('📊 Validation Results Summary'));
  console.log(chalk.blue('-'.repeat(35)));

  // Overall statistics
  const passRate = ((validationReport.passedTests / validationReport.testsExecuted) * 100);
  const passColor = passRate >= 80 ? chalk.green : passRate >= 60 ? chalk.yellow : chalk.red;
  
  console.log(`Total Checks: ${chalk.white(validationReport.totalChecks)}`);
  console.log(`Tests Executed: ${chalk.white(validationReport.testsExecuted)}`);
  console.log(`Tests Passed: ${chalk.green(validationReport.passedTests)}`);
  console.log(`Tests Failed: ${chalk.red(validationReport.failedTests)}`);
  console.log(`Pass Rate: ${passColor(passRate.toFixed(1) + '%')}`);
  console.log(`Falco Response Rate: ${chalk.cyan(validationReport.falcoResponseRate.toFixed(1) + '%')}`);

  // Category breakdown
  if (Object.keys(validationReport.summary.byCategory).length > 0) {
    console.log('\n' + chalk.blue('📋 Results by Category:'));
    for (const [category, stats] of Object.entries(validationReport.summary.byCategory) as any[]) {
      const categoryPassRate = stats.total > 0 ? ((stats.passed / stats.total) * 100).toFixed(1) : '0.0';
      const categoryColor = stats.passed === stats.total ? chalk.green : 
                           stats.passed > stats.failed ? chalk.yellow : chalk.red;
      
      console.log(`  ${category.padEnd(12)} ${categoryColor(`${stats.passed}/${stats.total} (${categoryPassRate}%)`)}`);
    }
  }

  // Critical issues
  if (validationReport.summary.criticalIssues.length > 0) {
    console.log('\n' + chalk.red('🚨 Critical Issues:'));
    validationReport.summary.criticalIssues.forEach((issue: string, index: number) => {
      console.log(chalk.red(`  ${index + 1}. ${issue}`));
    });
  }

  // Show some failed tests
  const failedTests = validationReport.results.filter((r: any) => !r.testExecuted || !r.falcoResponse);
  if (failedTests.length > 0) {
    console.log('\n' + chalk.yellow('⚠️  Failed Tests (showing first 5):'));
    failedTests.slice(0, 5).forEach((test: any, index: number) => {
      const reason = !test.testExecuted ? 'Test execution failed' :
                    !test.detectionTriggered ? 'Detection not triggered' :
                    !test.falcoResponse ? 'Falco did not respond' : 'Unknown failure';
      
      console.log(chalk.yellow(`  ${index + 1}. ${test.name} (${test.category})`));
      console.log(chalk.gray(`     Reason: ${reason}`));
      if (test.recommendedAction) {
        console.log(chalk.gray(`     Action: ${test.recommendedAction}`));
      }
    });
    
    if (failedTests.length > 5) {
      console.log(chalk.gray(`     ... and ${failedTests.length - 5} more (see full report)`));
    }
  }

  // Recommendations
  if (recommendations && recommendations.length > 0) {
    console.log('\n' + chalk.magenta('💡 Recommendations:'));
    recommendations.forEach((rec: string, index: number) => {
      console.log(chalk.magenta(`  ${index + 1}. ${rec}`));
    });
  }

  // Next steps
  if (nextSteps && nextSteps.length > 0) {
    console.log('\n' + chalk.cyan('📋 Next Steps:'));
    nextSteps.forEach((step: string) => {
      console.log(chalk.cyan(`  ${step}`));
    });
  }

  // Overall status
  console.log('\n' + chalk.blue('🎯 Overall Status:'));
  if (validationReport.passedTests === validationReport.testsExecuted) {
    console.log(chalk.green('✅ All security checks passed! Your system is well-protected.'));
  } else if (passRate >= 80) {
    console.log(chalk.yellow('⚠️  Most security checks passed, but some issues need attention.'));
  } else if (passRate >= 60) {
    console.log(chalk.yellow('⚠️  Significant security issues detected. Review and fix failing checks.'));
  } else {
    console.log(chalk.red('❌ Multiple critical security issues detected. Immediate action required.'));
  }
}

// Helper function to validate categories
export function validateCategories(categories: string[]): boolean {
  const validCategories = ['filesystem', 'process', 'network', 'privilege', 'container', 'kubernetes'];
  return categories.every(cat => validCategories.includes(cat));
}

// Helper function to validate mode
export function validateMode(mode: string): boolean {
  const validModes = ['safe', 'aggressive', 'simulation'];
  return validModes.includes(mode);
}