import { rbacManager } from '@core/rbac/RBACManager';
import { Logger } from '../utils/logger';
import chalk from 'chalk';
import ora from 'ora';

const logger = Logger.getInstance();

export interface AuthOptions {
  platform?: string;
  refresh?: boolean;
  verbose?: boolean;
}

/**
 * Auth status command - 모든 플랫폼의 인증 상태 확인
 */
export async function authStatusCommand(options: AuthOptions): Promise<void> {
  const spinner = ora('Checking authentication status...').start();

  try {
    await rbacManager.initialize();
    const systemStatus = await rbacManager.getSystemStatus();

    spinner.stop();

    console.log(chalk.blue('\n🔐 Authentication Status'));
    console.log(chalk.blue('=' .repeat(60)));

    // 플랫폼별 연결 상태 표시
    for (const [platform, connected] of Object.entries(systemStatus.platformConnections)) {
      const statusIcon = connected ? '✅' : '❌';
      const statusColor = connected ? chalk.green : chalk.red;
      const statusText = connected ? 'AUTHENTICATED' : 'NOT AUTHENTICATED';

      console.log(`${statusIcon} ${platform.toUpperCase()}: ${statusColor(statusText)}`);

      if (options.verbose && connected) {
        // 상세 정보 표시
        await displayPlatformDetails(platform);
      }
    }

    // 등록된 agent 정보
    console.log(chalk.gray(`\nRegistered Agents: ${systemStatus.registeredAgents.join(', ')}`));
    console.log(chalk.gray(`Last Check: ${systemStatus.lastStatusCheck.toLocaleString()}`));

    // 추천사항
    const unauthenticatedPlatforms = Object.entries(systemStatus.platformConnections)
      .filter(([_, connected]) => !connected)
      .map(([platform, _]) => platform);

    if (unauthenticatedPlatforms.length > 0) {
      console.log(chalk.yellow('\n💡 To authenticate:'));
      unauthenticatedPlatforms.forEach(platform => {
        console.log(chalk.yellow(`   • ${platform}: a2a auth login ${platform}`));
      });
    }

  } catch (error) {
    spinner.fail('Failed to check authentication status');
    logger.error(`❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Auth login command - 특정 플랫폼 로그인
 */
export async function authLoginCommand(platform: string, options: AuthOptions): Promise<void> {
  const spinner = ora(`Logging in to ${platform}...`).start();

  try {
    switch (platform.toLowerCase()) {
      case 'aws':
        await loginAWS(options);
        break;
      case 'gcp':
        await loginGCP(options);
        break;
      case 'azure':
        await loginAzure(options);
        break;
      default:
        throw new Error(`Unsupported platform: ${platform}`);
    }

    spinner.succeed(`Successfully logged in to ${platform}`);
    
    // 권한 캐시 갱신
    await rbacManager.refreshUserPermissions(await getCurrentUser());

  } catch (error) {
    spinner.fail(`Failed to login to ${platform}`);
    logger.error(`❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Auth refresh command - 모든 플랫폼 인증 갱신
 */
export async function authRefreshCommand(options: AuthOptions): Promise<void> {
  const spinner = ora('Refreshing authentication...').start();

  try {
    await rbacManager.initialize();
    const currentUser = await getCurrentUser();
    
    // 모든 권한 캐시 무효화
    rbacManager.invalidateAllPermissions();
    
    // 새로운 인증 상태 확인
    const systemStatus = await rbacManager.getSystemStatus();
    
    spinner.succeed('Authentication refreshed');

    console.log(chalk.green('\n✅ Authentication Refresh Complete'));
    console.log(chalk.gray(`User: ${currentUser}`));
    console.log(chalk.gray(`Active Platforms: ${systemStatus.registeredAgents.join(', ')}`));

  } catch (error) {
    spinner.fail('Failed to refresh authentication');
    logger.error(`❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Auth permissions command - 사용자 권한 요약
 */
export async function authPermissionsCommand(options: AuthOptions): Promise<void> {
  const spinner = ora('Checking user permissions...').start();

  try {
    await rbacManager.initialize();
    const currentUser = await getCurrentUser();
    const permissionSummary = await rbacManager.getUserPermissionSummary(currentUser);

    spinner.stop();

    console.log(chalk.blue('\n🔑 User Permissions Summary'));
    console.log(chalk.blue('=' .repeat(60)));

    console.log(chalk.white(`User: ${permissionSummary.user}`));
    console.log(chalk.white(`Risk Level: ${getRiskLevelDisplay(permissionSummary.riskLevel)}`));

    // 허용된 리소스
    console.log(chalk.green('\n✅ Allowed Resources:'));
    if (permissionSummary.allowedResources.length > 0) {
      permissionSummary.allowedResources.forEach(resource => {
        console.log(chalk.green(`   • ${resource}`));
      });
    } else {
      console.log(chalk.gray('   No resources accessible'));
    }

    // 접근 가능한 네임스페이스
    console.log(chalk.cyan('\n📁 Accessible Namespaces:'));
    if (permissionSummary.accessibleNamespaces.length > 0) {
      permissionSummary.accessibleNamespaces.forEach(namespace => {
        console.log(chalk.cyan(`   • ${namespace}`));
      });
    } else {
      console.log(chalk.gray('   No namespaces accessible'));
    }

    // 플랫폼 상태
    console.log(chalk.blue('\n🔗 Platform Status:'));
    for (const [platform, connected] of Object.entries(permissionSummary.platformStatus)) {
      const statusIcon = connected ? '✅' : '❌';
      const statusColor = connected ? chalk.green : chalk.red;
      console.log(`${statusIcon} ${platform}: ${statusColor(connected ? 'Connected' : 'Disconnected')}`);
    }

    console.log(chalk.gray(`\nLast Checked: ${permissionSummary.lastChecked.toLocaleString()}`));

  } catch (error) {
    spinner.fail('Failed to check permissions');
    logger.error(`❌ Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// 플랫폼별 로그인 구현
async function loginAWS(options: AuthOptions): Promise<void> {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const execAsync = promisify(exec);

  try {
    // AWS CLI 설치 확인
    await execAsync('aws --version');
    
    // AWS SSO 로그인 시도
    try {
      await execAsync('aws sso login');
    } catch {
      // SSO 실패시 일반 로그인 안내
      console.log(chalk.yellow('\n💡 AWS SSO login failed. Please configure AWS credentials:'));
      console.log(chalk.gray('   aws configure'));
      console.log(chalk.gray('   or set environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY'));
    }

    // 로그인 확인
    const { stdout } = await execAsync('aws sts get-caller-identity');
    const identity = JSON.parse(stdout);
    
    console.log(chalk.green(`✅ AWS authenticated as: ${identity.Arn}`));

  } catch (error) {
    throw new Error(`AWS login failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function loginGCP(options: AuthOptions): Promise<void> {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const execAsync = promisify(exec);

  try {
    // gcloud CLI 설치 확인
    await execAsync('gcloud version');
    
    // gcloud 로그인
    await execAsync('gcloud auth login');
    
    // 로그인 확인
    const { stdout } = await execAsync('gcloud auth list --filter=status:ACTIVE --format="value(account)"');
    const activeAccount = stdout.trim();
    
    if (activeAccount) {
      console.log(chalk.green(`✅ GCP authenticated as: ${activeAccount}`));
    } else {
      throw new Error('No active GCP account found');
    }

  } catch (error) {
    throw new Error(`GCP login failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function loginAzure(options: AuthOptions): Promise<void> {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const execAsync = promisify(exec);

  try {
    // Azure CLI 설치 확인
    await execAsync('az version');
    
    // Azure 로그인
    await execAsync('az login');
    
    // 로그인 확인
    const { stdout } = await execAsync('az account show');
    const account = JSON.parse(stdout);
    
    console.log(chalk.green(`✅ Azure authenticated as: ${account.user.name}`));

  } catch (error) {
    throw new Error(`Azure login failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// 플랫폼별 상세 정보 표시
async function displayPlatformDetails(platform: string): Promise<void> {
  const { exec } = await import('child_process');
  const { promisify } = await import('util');
  const execAsync = promisify(exec);

  try {
    switch (platform) {
      case 'kubernetes':
        const { stdout: context } = await execAsync('kubectl config current-context');
        const { stdout: cluster } = await execAsync('kubectl cluster-info --request-timeout=5s | head -1');
        console.log(chalk.gray(`     Context: ${context.trim()}`));
        console.log(chalk.gray(`     Cluster: ${cluster.trim()}`));
        break;

      case 'aws':
        const { stdout: awsIdentity } = await execAsync('aws sts get-caller-identity');
        const identity = JSON.parse(awsIdentity);
        console.log(chalk.gray(`     Account: ${identity.Account}`));
        console.log(chalk.gray(`     User: ${identity.Arn.split('/').pop()}`));
        break;

      case 'gcp':
        const { stdout: gcpAccount } = await execAsync('gcloud config get-value account');
        const { stdout: gcpProject } = await execAsync('gcloud config get-value project');
        console.log(chalk.gray(`     Account: ${gcpAccount.trim()}`));
        console.log(chalk.gray(`     Project: ${gcpProject.trim()}`));
        break;

      case 'azure':
        const { stdout: azureAccount } = await execAsync('az account show');
        const account = JSON.parse(azureAccount);
        console.log(chalk.gray(`     Subscription: ${account.name}`));
        console.log(chalk.gray(`     User: ${account.user.name}`));
        break;
    }
  } catch {
    // 상세 정보 조회 실패는 무시
  }
}

// 위험도 레벨 표시
function getRiskLevelDisplay(riskLevel: string): string {
  switch (riskLevel) {
    case 'high':
      return chalk.red('HIGH');
    case 'medium':
      return chalk.yellow('MEDIUM');
    case 'low':
      return chalk.green('LOW');
    default:
      return chalk.gray('UNKNOWN');
  }
}

// 현재 사용자 확인 (query.ts와 동일한 로직)
async function getCurrentUser(): Promise<string> {
  try {
    if (process.env.A2A_USER) {
      return process.env.A2A_USER;
    }

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

    if (process.env.USER || process.env.USERNAME) {
      return process.env.USER || process.env.USERNAME || 'unknown';
    }

    return 'current-user';
  } catch {
    return 'unknown-user';
  }
}