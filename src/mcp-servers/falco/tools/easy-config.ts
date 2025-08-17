import { BaseTool } from '@mcp-servers/base/Tool';
import { ToolResult } from '@core/types';
import { ConfigManager } from '../../../cli/utils/config';
import { Logger } from '../../../cli/utils/logger';

export class EasyConfigTool extends BaseTool {
  readonly name = 'easy_config';
  readonly description = 'Easy configuration management for common A2A settings using natural language. Simplifies complex configuration tasks.';
  readonly inputSchema = {
    type: 'object' as const,
    properties: {
      action: {
        type: 'string',
        enum: ['quick_setup', 'preset', 'auto_detect', 'guided_setup', 'import_from', 'export_to', 'backup', 'restore'],
        description: 'Configuration action to perform',
        default: 'quick_setup'
      },
      preset: {
        type: 'string',
        enum: ['development', 'staging', 'production', 'high_security', 'minimal', 'cloud_native', 'on_premise'],
        description: 'Configuration preset to apply'
      },
      source: {
        type: 'string',
        enum: ['environment', 'file', 'kubernetes', 'docker_compose', 'helm_values', 'aws_secrets', 'vault'],
        description: 'Source to import configuration from'
      },
      target: {
        type: 'string',
        enum: ['environment', 'file', 'kubernetes_configmap', 'kubernetes_secret', 'helm_values'],
        description: 'Target to export configuration to'
      },
      filePath: {
        type: 'string',
        description: 'File path for import/export operations'
      },
      namespace: {
        type: 'string',
        description: 'Kubernetes namespace for configuration operations',
        default: 'default'
      },
      autoFix: {
        type: 'boolean',
        description: 'Automatically fix configuration issues',
        default: false
      },
      interactive: {
        type: 'boolean',
        description: 'Use interactive prompts',
        default: false
      },
      platform: {
        type: 'string',
        enum: ['aws', 'gcp', 'azure', 'kubernetes', 'docker', 'local'],
        description: 'Target platform for configuration'
      },
      includeSecrets: {
        type: 'boolean',
        description: 'Include secret values in operations',
        default: false
      }
    },
    required: []
  };

  private configManager = ConfigManager.getInstance();
  private logger = Logger.getInstance();

  async execute(params: any): Promise<ToolResult> {
    if (!this.validateParams(params)) {
      return this.createErrorResult('Invalid parameters provided');
    }

    try {
      const {
        action = 'quick_setup',
        preset,
        source,
        target,
        filePath,
        namespace = 'default',
        autoFix = false,
        interactive = false,
        platform,
        includeSecrets = false
      } = params;

      switch (action) {
        case 'quick_setup':
          return await this.quickSetup(platform, autoFix);
        
        case 'preset':
          return await this.applyPreset(preset, platform);
        
        case 'auto_detect':
          return await this.autoDetectConfiguration(platform);
        
        case 'guided_setup':
          return await this.guidedSetup(platform);
        
        case 'import_from':
          return await this.importConfiguration(source, filePath, namespace);
        
        case 'export_to':
          return await this.exportConfiguration(target, filePath, namespace, includeSecrets);
        
        case 'backup':
          return await this.backupConfiguration();
        
        case 'restore':
          return await this.restoreConfiguration(filePath);
        
        default:
          return this.createErrorResult(`Unknown action: ${action}`);
      }

    } catch (error) {
      return this.createErrorResult(`Configuration operation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async quickSetup(platform?: string, autoFix = false): Promise<ToolResult> {
    this.logger.info('Starting quick setup...');

    // Auto-detect platform if not specified
    const detectedPlatform = platform || await this.detectPlatform();
    
    // Get appropriate preset for platform
    const presetName = this.getPresetForPlatform(detectedPlatform);
    
    // Apply preset configuration
    const config = this.getPresetConfiguration(presetName);
    
    // Auto-detect services and update configuration
    const detectedServices = await this.detectServices();
    this.updateConfigWithDetectedServices(config, detectedServices);

    // Validate and fix configuration if requested
    if (autoFix) {
      await this.autoFixConfiguration(config);
    }

    // Save configuration
    await this.configManager.saveConfig(config);

    return this.createSuccessResult({
      message: `Quick setup completed for ${detectedPlatform} platform`,
      platform: detectedPlatform,
      preset: presetName,
      detected_services: detectedServices,
      next_steps: [
        'Test configuration: a2a doctor',
        'Start monitoring: a2a monitor',
        'Configure notifications: a2a query "setup slack notifications"'
      ]
    });
  }

  private async applyPreset(preset: string, platform?: string): Promise<ToolResult> {
    if (!preset) {
      return this.createErrorResult('Preset name is required');
    }

    const config = this.getPresetConfiguration(preset);
    
    // Customize preset based on platform
    if (platform) {
      this.customizeConfigForPlatform(config, platform);
    }

    await this.configManager.saveConfig(config);

    return this.createSuccessResult({
      message: `Applied ${preset} preset configuration`,
      preset,
      platform,
      configuration: config,
      description: this.getPresetDescription(preset)
    });
  }

  private async autoDetectConfiguration(platform?: string): Promise<ToolResult> {
    const detectedServices = await this.detectServices();
    const detectedPlatform = platform || await this.detectPlatform();
    
    const config = await this.configManager.getConfig();
    this.updateConfigWithDetectedServices(config, detectedServices);
    
    // Apply platform-specific optimizations
    this.optimizeConfigForPlatform(config, detectedPlatform);

    await this.configManager.saveConfig(config);

    return this.createSuccessResult({
      message: 'Auto-detection completed and configuration updated',
      platform: detectedPlatform,
      detected_services: detectedServices,
      recommendations: this.generateRecommendations(detectedServices, detectedPlatform)
    });
  }

  private async guidedSetup(platform?: string): Promise<ToolResult> {
    // This would typically use interactive prompts, but for MCP we'll return guided steps
    const steps = this.getGuidedSetupSteps(platform);
    
    return this.createSuccessResult({
      message: 'Guided setup instructions generated',
      platform,
      setup_steps: steps,
      note: 'Use "a2a query configure notifications interactive" for interactive setup'
    });
  }

  private async importConfiguration(source: string, filePath?: string, namespace?: string): Promise<ToolResult> {
    switch (source) {
      case 'environment':
        return await this.importFromEnvironment();
      
      case 'file':
        if (!filePath) {
          return this.createErrorResult('File path is required for file import');
        }
        return await this.importFromFile(filePath);
      
      case 'kubernetes':
        return await this.importFromKubernetes(namespace!);
      
      default:
        return this.createErrorResult(`Unsupported import source: ${source}`);
    }
  }

  private async exportConfiguration(target: string, filePath?: string, namespace?: string, includeSecrets = false): Promise<ToolResult> {
    const config = await this.configManager.getConfig();
    
    switch (target) {
      case 'environment':
        return await this.exportToEnvironment(config);
      
      case 'file':
        if (!filePath) {
          return this.createErrorResult('File path is required for file export');
        }
        return await this.exportToFile(config, filePath);
      
      case 'kubernetes_configmap':
        return await this.exportToKubernetesConfigMap(config, namespace!, includeSecrets);
      
      case 'kubernetes_secret':
        return await this.exportToKubernetesSecret(config, namespace!);
      
      default:
        return this.createErrorResult(`Unsupported export target: ${target}`);
    }
  }

  private async backupConfiguration(): Promise<ToolResult> {
    try {
      const backupPath = await this.configManager.backupConfig();
      return this.createSuccessResult({
        message: 'Configuration backed up successfully',
        backup_path: backupPath,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      return this.createErrorResult(`Backup failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async restoreConfiguration(filePath?: string): Promise<ToolResult> {
    if (!filePath) {
      return this.createErrorResult('Backup file path is required for restore');
    }

    try {
      await this.configManager.restoreConfig(filePath);
      return this.createSuccessResult({
        message: 'Configuration restored successfully',
        restored_from: filePath,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      return this.createErrorResult(`Restore failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  // Helper methods for platform and service detection
  private async detectPlatform(): Promise<string> {
    // Check for Kubernetes environment
    if (process.env.KUBERNETES_SERVICE_HOST) {
      return 'kubernetes';
    }
    
    // Check for cloud provider metadata services
    try {
      const axios = await import('axios');
      
      // AWS
      try {
        await axios.default.get('http://169.254.169.254/latest/meta-data/', { timeout: 1000 });
        return 'aws';
      } catch {}
      
      // GCP
      try {
        await axios.default.get('http://metadata.google.internal/computeMetadata/v1/', {
          timeout: 1000,
          headers: { 'Metadata-Flavor': 'Google' }
        });
        return 'gcp';
      } catch {}
      
      // Azure
      try {
        await axios.default.get('http://169.254.169.254/metadata/instance', {
          timeout: 1000,
          headers: { 'Metadata': 'true' }
        });
        return 'azure';
      } catch {}
      
    } catch {}
    
    // Check for Docker environment
    if (process.env.DOCKER_HOST || require('fs').existsSync('/.dockerenv')) {
      return 'docker';
    }
    
    return 'local';
  }

  private async detectServices(): Promise<any> {
    const services: any = {
      prometheus: { detected: false, url: null },
      falco: { detected: false, socket: null },
      kubernetes: { detected: false, context: null },
      alertmanager: { detected: false, url: null }
    };

    // Detect Prometheus
    const prometheusUrls = [
      'http://localhost:9090',
      'http://prometheus:9090',
      'http://prometheus.monitoring.svc.cluster.local:9090'
    ];

    for (const url of prometheusUrls) {
      try {
        const axios = await import('axios');
        const response = await axios.default.get(`${url}/-/healthy`, { timeout: 2000 });
        if (response.status === 200) {
          services.prometheus = { detected: true, url };
          break;
        }
      } catch {}
    }

    // Detect Falco
    const falcoSockets = [
      '/var/run/falco.sock',
      '/run/falco/falco.sock',
      '/tmp/falco.sock'
    ];

    for (const socket of falcoSockets) {
      if (require('fs').existsSync(socket)) {
        services.falco = { detected: true, socket };
        break;
      }
    }

    // Detect Kubernetes
    if (process.env.KUBECONFIG || require('fs').existsSync(require('path').join(require('os').homedir(), '.kube/config'))) {
      services.kubernetes = { detected: true, context: 'detected' };
    }

    return services;
  }

  private getPresetConfiguration(preset: string): any {
    const baseConfig = {
      claudeCode: { timeout: 30000, maxRetries: 3 },
      monitoring: {
        prometheusUrl: 'http://localhost:9090',
        falcoSocket: '/var/run/falco.sock'
      },
      notifications: {
        slack: { enabled: false, webhookUrl: '' },
        pagerduty: { enabled: false, apiKey: '' }
      },
      debug: false,
      logLevel: 'info'
    };

    switch (preset) {
      case 'development':
        return {
          ...baseConfig,
          debug: true,
          logLevel: 'debug',
          claudeCode: { timeout: 60000, maxRetries: 5 }
        };

      case 'production':
        return {
          ...baseConfig,
          logLevel: 'warn',
          claudeCode: { timeout: 20000, maxRetries: 2 },
          notifications: {
            slack: { enabled: true, webhookUrl: '' },
            pagerduty: { enabled: true, apiKey: '' }
          }
        };

      case 'high_security':
        return {
          ...baseConfig,
          logLevel: 'info',
          claudeCode: { timeout: 15000, maxRetries: 1 },
          notifications: {
            slack: { enabled: true, webhookUrl: '' },
            pagerduty: { enabled: true, apiKey: '' }
          }
        };

      case 'cloud_native':
        return {
          ...baseConfig,
          monitoring: {
            prometheusUrl: 'http://prometheus.monitoring.svc.cluster.local:9090',
            falcoSocket: '/var/run/falco.sock'
          }
        };

      default:
        return baseConfig;
    }
  }

  private getPresetForPlatform(platform: string): string {
    switch (platform) {
      case 'kubernetes':
      case 'aws':
      case 'gcp':
      case 'azure':
        return 'cloud_native';
      case 'docker':
        return 'development';
      case 'local':
        return 'minimal';
      default:
        return 'development';
    }
  }

  private updateConfigWithDetectedServices(config: any, services: any): void {
    if (services.prometheus.detected) {
      config.monitoring.prometheusUrl = services.prometheus.url;
    }
    
    if (services.falco.detected) {
      config.monitoring.falcoSocket = services.falco.socket;
    }
  }

  private customizeConfigForPlatform(config: any, platform: string): void {
    switch (platform) {
      case 'kubernetes':
        config.monitoring.prometheusUrl = 'http://prometheus.monitoring.svc.cluster.local:9090';
        break;
      case 'aws':
        // AWS-specific optimizations
        config.claudeCode.timeout = 45000;
        break;
      case 'gcp':
        // GCP-specific optimizations
        break;
      case 'azure':
        // Azure-specific optimizations
        break;
    }
  }

  private optimizeConfigForPlatform(config: any, platform: string): void {
    this.customizeConfigForPlatform(config, platform);
  }

  private async autoFixConfiguration(config: any): Promise<void> {
    // Auto-fix common configuration issues
    if (!config.monitoring.prometheusUrl.startsWith('http')) {
      config.monitoring.prometheusUrl = 'http://' + config.monitoring.prometheusUrl;
    }
    
    if (config.claudeCode.timeout < 5000) {
      config.claudeCode.timeout = 5000;
    }
    
    if (config.claudeCode.maxRetries < 1) {
      config.claudeCode.maxRetries = 1;
    }
  }

  private getGuidedSetupSteps(platform?: string): string[] {
    const baseSteps = [
      'Initialize configuration: a2a config init',
      'Configure monitoring endpoints',
      'Set up notification channels',
      'Test configuration: a2a doctor',
      'Start monitoring: a2a monitor'
    ];

    if (platform === 'kubernetes') {
      return [
        'Verify kubectl access: kubectl cluster-info',
        ...baseSteps,
        'Deploy monitoring stack if needed',
        'Configure RBAC permissions'
      ];
    }

    return baseSteps;
  }

  private generateRecommendations(services: any, platform: string): string[] {
    const recommendations: string[] = [];

    if (!services.prometheus.detected) {
      recommendations.push('Install Prometheus for metrics collection');
    }

    if (!services.falco.detected) {
      recommendations.push('Install Falco for runtime security monitoring');
    }

    if (platform === 'kubernetes' && !services.kubernetes.detected) {
      recommendations.push('Configure kubectl access to your cluster');
    }

    recommendations.push('Set up notification channels for alerting');
    recommendations.push('Configure log aggregation for better observability');

    return recommendations;
  }

  private async importFromEnvironment(): Promise<ToolResult> {
    const config = await this.configManager.getConfigWithEnvOverrides();
    await this.configManager.saveConfig(config);
    
    return this.createSuccessResult({
      message: 'Configuration imported from environment variables',
      imported_vars: this.getImportedEnvVars()
    });
  }

  private async importFromFile(filePath: string): Promise<ToolResult> {
    try {
      const fs = await import('fs/promises');
      const content = await fs.readFile(filePath, 'utf8');
      const format = filePath.endsWith('.yaml') || filePath.endsWith('.yml') ? 'yaml' : 'json';
      
      await this.configManager.importConfig(content, format);
      
      return this.createSuccessResult({
        message: `Configuration imported from ${filePath}`,
        format,
        file_path: filePath
      });
    } catch (error) {
      return this.createErrorResult(`Import failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async importFromKubernetes(namespace: string): Promise<ToolResult> {
    // This would require kubectl integration
    return this.createSuccessResult({
      message: 'Kubernetes import not yet implemented',
      namespace,
      note: 'Use kubectl to export ConfigMaps and import via file'
    });
  }

  private async exportToEnvironment(config: any): Promise<ToolResult> {
    const envFormat = await this.configManager.exportConfig('env');
    
    return this.createSuccessResult({
      message: 'Configuration exported as environment variables',
      env_format: envFormat,
      instructions: 'Copy the environment variables to your shell or .env file'
    });
  }

  private async exportToFile(config: any, filePath: string): Promise<ToolResult> {
    try {
      const fs = await import('fs/promises');
      const format = filePath.endsWith('.yaml') || filePath.endsWith('.yml') ? 'yaml' : 'json';
      const content = await this.configManager.exportConfig(format);
      
      await fs.writeFile(filePath, content, 'utf8');
      
      return this.createSuccessResult({
        message: `Configuration exported to ${filePath}`,
        format,
        file_path: filePath
      });
    } catch (error) {
      return this.createErrorResult(`Export failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async exportToKubernetesConfigMap(config: any, namespace: string, includeSecrets: boolean): Promise<ToolResult> {
    // Generate Kubernetes ConfigMap YAML
    const configMapYaml = this.generateKubernetesConfigMap(config, namespace, includeSecrets);
    
    return this.createSuccessResult({
      message: 'Kubernetes ConfigMap generated',
      namespace,
      yaml: configMapYaml,
      instructions: 'Apply with: kubectl apply -f <filename>'
    });
  }

  private async exportToKubernetesSecret(config: any, namespace: string): Promise<ToolResult> {
    // Generate Kubernetes Secret YAML for sensitive data
    const secretYaml = this.generateKubernetesSecret(config, namespace);
    
    return this.createSuccessResult({
      message: 'Kubernetes Secret generated',
      namespace,
      yaml: secretYaml,
      instructions: 'Apply with: kubectl apply -f <filename>'
    });
  }

  private getImportedEnvVars(): string[] {
    return [
      'A2A_PROMETHEUS_URL',
      'A2A_FALCO_SOCKET',
      'A2A_SLACK_WEBHOOK_URL',
      'A2A_PAGERDUTY_API_KEY',
      'A2A_DEBUG',
      'A2A_LOG_LEVEL'
    ];
  }

  private generateKubernetesConfigMap(config: any, namespace: string, includeSecrets: boolean): string {
    const data: any = {
      'prometheus-url': config.monitoring.prometheusUrl,
      'falco-socket': config.monitoring.falcoSocket,
      'log-level': config.logLevel,
      'debug': config.debug.toString()
    };

    if (includeSecrets) {
      if (config.notifications.slack.webhookUrl) {
        data['slack-webhook-url'] = config.notifications.slack.webhookUrl;
      }
      if (config.notifications.pagerduty.apiKey) {
        data['pagerduty-api-key'] = config.notifications.pagerduty.apiKey;
      }
    }

    return `apiVersion: v1
kind: ConfigMap
metadata:
  name: a2a-config
  namespace: ${namespace}
data:
${Object.entries(data).map(([key, value]) => `  ${key}: "${value}"`).join('\\n')}`;
  }

  private generateKubernetesSecret(config: any, namespace: string): string {
    const data: any = {};

    if (config.notifications.slack.webhookUrl) {
      data['slack-webhook-url'] = Buffer.from(config.notifications.slack.webhookUrl).toString('base64');
    }
    if (config.notifications.pagerduty.apiKey) {
      data['pagerduty-api-key'] = Buffer.from(config.notifications.pagerduty.apiKey).toString('base64');
    }

    return `apiVersion: v1
kind: Secret
metadata:
  name: a2a-secrets
  namespace: ${namespace}
type: Opaque
data:
${Object.entries(data).map(([key, value]) => `  ${key}: ${value}`).join('\\n')}`;
  }

  private getPresetDescription(preset: string): string {
    const descriptions: Record<string, string> = {
      development: 'Optimized for development with debug logging and relaxed timeouts',
      staging: 'Balanced configuration for staging environments',
      production: 'Production-ready with monitoring and alerting enabled',
      high_security: 'Security-focused configuration with strict timeouts and comprehensive monitoring',
      minimal: 'Minimal configuration for resource-constrained environments',
      cloud_native: 'Optimized for cloud-native and Kubernetes deployments',
      on_premise: 'Configured for on-premise infrastructure'
    };
    
    return descriptions[preset] || 'Custom configuration preset';
  }
}