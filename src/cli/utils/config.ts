import { readFile, writeFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { Configuration } from '@core/types';
import { Logger } from './logger';

const logger = Logger.getInstance();

export class ConfigManager {
  private static instance: ConfigManager;
  private configPath: string;
  private configDir: string;
  private cachedConfig: Configuration | null = null;

  private constructor() {
    const homeDir = process.env.HOME || process.env.USERPROFILE || process.cwd();
    this.configDir = process.env.A2A_CONFIG_DIR || path.join(homeDir, '.a2a');
    this.configPath = process.env.A2A_CONFIG_PATH || path.join(this.configDir, 'config.json');
  }

  public static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  public async getConfig(): Promise<Configuration> {
    if (this.cachedConfig) {
      return this.cachedConfig;
    }

    try {
      if (existsSync(this.configPath)) {
        const configContent = await readFile(this.configPath, 'utf8');
        const config = JSON.parse(configContent);
        this.cachedConfig = { ...this.getDefaultConfig(), ...config };
      } else {
        this.cachedConfig = this.getDefaultConfig();
        await this.ensureConfigDirectory();
        await this.saveConfig(this.cachedConfig);
      }

      return this.cachedConfig;
    } catch (error) {
      logger.error(`Failed to load config: ${error instanceof Error ? error.message : 'Unknown error'}`);
      this.cachedConfig = this.getDefaultConfig();
      return this.cachedConfig;
    }
  }

  public async saveConfig(config: Configuration): Promise<void> {
    try {
      await this.ensureConfigDirectory();
      await writeFile(this.configPath, JSON.stringify(config, null, 2), 'utf8');
      this.cachedConfig = config;
      logger.debug('Configuration saved successfully');
    } catch (error) {
      logger.error(`Failed to save config: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }
  }

  public async getValue(key: string): Promise<any> {
    const config = await this.getConfig();
    return this.getNestedValue(config, key);
  }

  public async setValue(key: string, value: any): Promise<void> {
    const config = await this.getConfig();
    this.setNestedValue(config, key, value);
    await this.saveConfig(config);
    logger.debug(`Configuration value set: ${key} = ${typeof value === 'object' ? JSON.stringify(value) : value}`);
  }

  public async resetConfig(): Promise<void> {
    const defaultConfig = this.getDefaultConfig();
    await this.saveConfig(defaultConfig);
    logger.info('Configuration reset to defaults');
  }

  public async initializeConfig(force = false): Promise<void> {
    if (existsSync(this.configPath) && !force) {
      logger.info('Configuration already exists. Use --force to overwrite.');
      return;
    }

    const config = this.getDefaultConfig();
    
    // Try to detect system-specific defaults
    config.monitoring.prometheusUrl = await this.detectPrometheusUrl();
    config.monitoring.falcoSocket = await this.detectFalcoSocket();
    
    await this.saveConfig(config);
    logger.success('Configuration initialized successfully');
  }

  public getConfigPath(): string {
    return this.configPath;
  }

  public getConfigDirectory(): string {
    return this.configDir;
  }

  public async validateConfig(): Promise<{ valid: boolean; errors: string[] }> {
    const config = await this.getConfig();
    const errors: string[] = [];

    // Validate Claude Code settings
    if (!config.claudeCode.timeout || config.claudeCode.timeout < 1000) {
      errors.push('claudeCode.timeout must be at least 1000ms');
    }

    if (!config.claudeCode.maxRetries || config.claudeCode.maxRetries < 1) {
      errors.push('claudeCode.maxRetries must be at least 1');
    }

    // Validate monitoring settings
    if (!config.monitoring.prometheusUrl || !this.isValidUrl(config.monitoring.prometheusUrl)) {
      errors.push('monitoring.prometheusUrl must be a valid URL');
    }

    // Validate notification settings
    if (config.notifications.slack.enabled && !config.notifications.slack.webhookUrl) {
      errors.push('notifications.slack.webhookUrl is required when Slack notifications are enabled');
    }

    if (config.notifications.pagerduty.enabled && !config.notifications.pagerduty.apiKey) {
      errors.push('notifications.pagerduty.apiKey is required when PagerDuty notifications are enabled');
    }

    // Validate log level
    const validLogLevels = ['error', 'warn', 'info', 'verbose', 'debug'];
    if (!validLogLevels.includes(config.logLevel)) {
      errors.push(`logLevel must be one of: ${validLogLevels.join(', ')}`);
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  public async listSettings(showSecrets = false): Promise<Record<string, any>> {
    const config = await this.getConfig();
    
    if (!showSecrets) {
      // Mask sensitive values
      const maskedConfig = JSON.parse(JSON.stringify(config));
      this.maskSecrets(maskedConfig);
      return maskedConfig;
    }

    return config;
  }

  private getDefaultConfig(): Configuration {
    return {
      claudeCode: {
        timeout: 30000,
        maxRetries: 3
      },
      monitoring: {
        prometheusUrl: 'http://localhost:9090',
        falcoSocket: '/var/run/falco.sock'
      },
      notifications: {
        slack: {
          enabled: false,
          webhookUrl: ''
        },
        pagerduty: {
          enabled: false,
          apiKey: ''
        }
      },
      debug: false,
      logLevel: 'info'
    };
  }

  private async ensureConfigDirectory(): Promise<void> {
    if (!existsSync(this.configDir)) {
      await mkdir(this.configDir, { recursive: true });
    }
  }

  private getNestedValue(obj: any, key: string): any {
    return key.split('.').reduce((current, part) => current?.[part], obj);
  }

  private setNestedValue(obj: any, key: string, value: any): void {
    const keys = key.split('.');
    const lastKey = keys.pop()!;
    const target = keys.reduce((current, part) => {
      if (!(part in current)) {
        current[part] = {};
      }
      return current[part];
    }, obj);
    target[lastKey] = value;
  }

  private async detectPrometheusUrl(): Promise<string> {
    // Try common Prometheus URLs
    const commonUrls = [
      'http://localhost:9090',
      'http://127.0.0.1:9090',
      'http://prometheus:9090'
    ];

    const axios = await import('axios');
    
    for (const url of commonUrls) {
      try {
        const response = await axios.default.get(`${url}/-/healthy`, { timeout: 2000 });
        if (response.status === 200) {
          logger.debug(`Detected Prometheus at ${url}`);
          return url;
        }
      } catch {
        continue;
      }
    }

    return 'http://localhost:9090'; // Default fallback
  }

  private async detectFalcoSocket(): Promise<string> {
    const commonSockets = [
      '/var/run/falco.sock',
      '/run/falco/falco.sock',
      '/tmp/falco.sock'
    ];

    for (const socket of commonSockets) {
      if (existsSync(socket)) {
        logger.debug(`Detected Falco socket at ${socket}`);
        return socket;
      }
    }

    return '/var/run/falco.sock'; // Default fallback
  }

  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  private maskSecrets(obj: any, path = ''): void {
    for (const [key, value] of Object.entries(obj)) {
      const currentPath = path ? `${path}.${key}` : key;
      
      if (typeof value === 'object' && value !== null) {
        this.maskSecrets(value, currentPath);
      } else if (this.isSensitiveKey(key)) {
        obj[key] = value ? '*'.repeat(8) : '';
      }
    }
  }

  private isSensitiveKey(key: string): boolean {
    const sensitiveKeys = ['apikey', 'token', 'secret', 'password', 'webhookurl'];
    return sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive));
  }

  // Environment variable overrides
  public async getConfigWithEnvOverrides(): Promise<Configuration> {
    const config = await this.getConfig();
    
    // Apply environment variable overrides
    if (process.env.A2A_PROMETHEUS_URL) {
      config.monitoring.prometheusUrl = process.env.A2A_PROMETHEUS_URL;
    }
    
    if (process.env.A2A_FALCO_SOCKET) {
      config.monitoring.falcoSocket = process.env.A2A_FALCO_SOCKET;
    }
    
    if (process.env.A2A_SLACK_WEBHOOK_URL) {
      config.notifications.slack.webhookUrl = process.env.A2A_SLACK_WEBHOOK_URL;
      config.notifications.slack.enabled = true;
    }
    
    if (process.env.A2A_PAGERDUTY_API_KEY) {
      config.notifications.pagerduty.apiKey = process.env.A2A_PAGERDUTY_API_KEY;
      config.notifications.pagerduty.enabled = true;
    }
    
    if (process.env.A2A_DEBUG === 'true') {
      config.debug = true;
    }
    
    if (process.env.A2A_LOG_LEVEL) {
      config.logLevel = process.env.A2A_LOG_LEVEL as any;
    }

    return config;
  }

  // Method to export config in different formats
  public async exportConfig(format: 'json' | 'yaml' | 'env' = 'json'): Promise<string> {
    const config = await this.getConfig();
    
    switch (format) {
      case 'json':
        return JSON.stringify(config, null, 2);
      
      case 'yaml':
        const yaml = await import('yaml');
        return yaml.stringify(config);
      
      case 'env':
        return this.configToEnvFormat(config);
      
      default:
        return JSON.stringify(config, null, 2);
    }
  }

  private configToEnvFormat(config: Configuration): string {
    const envVars: string[] = [];
    
    envVars.push(`A2A_PROMETHEUS_URL=${config.monitoring.prometheusUrl}`);
    envVars.push(`A2A_FALCO_SOCKET=${config.monitoring.falcoSocket}`);
    
    if (config.notifications.slack.enabled) {
      envVars.push(`A2A_SLACK_WEBHOOK_URL=${config.notifications.slack.webhookUrl}`);
    }
    
    if (config.notifications.pagerduty.enabled) {
      envVars.push(`A2A_PAGERDUTY_API_KEY=${config.notifications.pagerduty.apiKey}`);
    }
    
    envVars.push(`A2A_DEBUG=${config.debug}`);
    envVars.push(`A2A_LOG_LEVEL=${config.logLevel}`);
    
    return envVars.join('\\n');
  }

  // Method to import config from different sources
  public async importConfig(source: string, format: 'json' | 'yaml' = 'json'): Promise<void> {
    let configData: any;
    
    switch (format) {
      case 'json':
        configData = JSON.parse(source);
        break;
      
      case 'yaml':
        const yaml = await import('yaml');
        configData = yaml.parse(source);
        break;
      
      default:
        throw new Error(`Unsupported import format: ${format}`);
    }
    
    // Validate imported config
    const mergedConfig = { ...this.getDefaultConfig(), ...configData };
    const validation = await this.validateConfig();
    
    if (!validation.valid) {
      throw new Error(`Invalid configuration: ${validation.errors.join(', ')}`);
    }
    
    await this.saveConfig(mergedConfig);
    logger.success('Configuration imported successfully');
  }

  // Method to backup current config
  public async backupConfig(): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(this.configDir, `config-backup-${timestamp}.json`);
    
    const config = await this.getConfig();
    await writeFile(backupPath, JSON.stringify(config, null, 2), 'utf8');
    
    logger.info(`Configuration backed up to ${backupPath}`);
    return backupPath;
  }

  // Method to restore from backup
  public async restoreConfig(backupPath: string): Promise<void> {
    if (!existsSync(backupPath)) {
      throw new Error(`Backup file not found: ${backupPath}`);
    }
    
    const backupContent = await readFile(backupPath, 'utf8');
    await this.importConfig(backupContent, 'json');
    
    logger.success(`Configuration restored from ${backupPath}`);
  }
}