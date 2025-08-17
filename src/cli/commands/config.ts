import { ConfigManager } from '../utils/config';
import { Logger } from '../utils/logger';
import chalk from 'chalk';
import inquirer from 'inquirer';

const configManager = ConfigManager.getInstance();
const logger = Logger.getInstance();

export const configCommand = {
  async init(options: { force?: boolean }): Promise<void> {
    try {
      await configManager.initializeConfig(options.force);
      console.log(chalk.green('✅ Configuration initialized successfully'));
      console.log(chalk.blue(`📁 Config location: ${configManager.getConfigPath()}`));
    } catch (error) {
      logger.errorMessage(`Failed to initialize configuration: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  },

  async get(key: string): Promise<void> {
    try {
      const value = await configManager.getValue(key);
      if (value === undefined) {
        console.log(chalk.yellow(`Configuration key '${key}' not found`));
      } else {
        console.log(chalk.blue(`${key}: ${typeof value === 'object' ? JSON.stringify(value, null, 2) : value}`));
      }
    } catch (error) {
      logger.errorMessage(`Failed to get configuration value: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  },

  async set(key: string, value: string, options: { secure?: boolean }): Promise<void> {
    try {
      // Parse value as JSON if it looks like JSON, otherwise treat as string
      let parsedValue: any = value;
      try {
        if (value.startsWith('{') || value.startsWith('[') || value === 'true' || value === 'false' || /^\\d+$/.test(value)) {
          parsedValue = JSON.parse(value);
        }
      } catch {
        // Keep as string if JSON parsing fails
      }

      await configManager.setValue(key, parsedValue);
      console.log(chalk.green(`✅ Configuration updated: ${key}`));
      
      if (options.secure) {
        console.log(chalk.blue('🔒 Value stored securely'));
      }
    } catch (error) {
      logger.errorMessage(`Failed to set configuration value: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  },

  async list(options: { showSecrets?: boolean }): Promise<void> {
    try {
      const settings = await configManager.listSettings(options.showSecrets);
      console.log(chalk.blue('📋 A2A Configuration:'));
      console.log(JSON.stringify(settings, null, 2));
    } catch (error) {
      logger.errorMessage(`Failed to list configuration: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  },

  async reset(options: { confirm?: boolean }): Promise<void> {
    try {
      if (!options.confirm) {
        const { confirmReset } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirmReset',
            message: 'Are you sure you want to reset configuration to defaults?',
            default: false
          }
        ]);

        if (!confirmReset) {
          console.log(chalk.yellow('Configuration reset cancelled'));
          return;
        }
      }

      await configManager.resetConfig();
      console.log(chalk.green('✅ Configuration reset to defaults'));
    } catch (error) {
      logger.errorMessage(`Failed to reset configuration: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  }
};