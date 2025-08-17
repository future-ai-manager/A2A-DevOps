import { BaseTool } from '@mcp-servers/base/Tool';
import { ToolResult } from '@core/types';
import { ConfigManager } from '../../../cli/utils/config';
import { Logger } from '../../../cli/utils/logger';
import inquirer from 'inquirer';

export class ConfigureNotificationsTool extends BaseTool {
  readonly name = 'configure_notifications';
  readonly description = 'Configure notification settings using natural language commands. Supports Slack, PagerDuty, and other notification channels.';
  readonly inputSchema = {
    type: 'object' as const,
    properties: {
      action: {
        type: 'string',
        enum: ['setup', 'configure', 'enable', 'disable', 'test', 'list', 'update', 'remove'],
        description: 'Action to perform',
        default: 'setup'
      },
      channel: {
        type: 'string',
        enum: ['slack', 'pagerduty', 'email', 'webhook', 'all'],
        description: 'Notification channel to configure'
      },
      webhookUrl: {
        type: 'string',
        description: 'Slack webhook URL for Slack notifications',
        format: 'uri'
      },
      slackChannel: {
        type: 'string',
        description: 'Slack channel name (e.g., #security-alerts)'
      },
      pagerdutyApiKey: {
        type: 'string',
        description: 'PagerDuty API key for incident management'
      },
      pagerdutyServiceKey: {
        type: 'string',
        description: 'PagerDuty service integration key'
      },
      enabled: {
        type: 'boolean',
        description: 'Enable or disable the notification channel'
      },
      testMessage: {
        type: 'string',
        description: 'Custom test message to send'
      },
      severity: {
        type: 'string',
        enum: ['low', 'medium', 'high', 'critical', 'all'],
        description: 'Configure notifications for specific severity levels',
        default: 'medium'
      },
      interactive: {
        type: 'boolean',
        description: 'Use interactive setup wizard',
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
        action = 'setup',
        channel,
        webhookUrl,
        slackChannel,
        pagerdutyApiKey,
        pagerdutyServiceKey,
        enabled = true,
        testMessage,
        severity = 'medium',
        interactive = false
      } = params;

      switch (action) {
        case 'setup':
          if (interactive) {
            return await this.interactiveSetup();
          }
          return await this.setupNotifications(params);
        
        case 'configure':
          return await this.configureChannel(channel, params);
        
        case 'enable':
          return await this.enableChannel(channel, true);
        
        case 'disable':
          return await this.enableChannel(channel, false);
        
        case 'test':
          return await this.testChannel(channel, testMessage);
        
        case 'list':
          return await this.listChannels();
        
        case 'update':
          return await this.updateChannel(channel, params);
        
        case 'remove':
          return await this.removeChannel(channel);
        
        default:
          return this.createErrorResult(`Unknown action: ${action}`);
      }

    } catch (error) {
      return this.createErrorResult(`Failed to configure notifications: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async interactiveSetup(): Promise<ToolResult> {
    try {
      console.log('🔧 Welcome to the A2A Notification Setup Wizard!');
      console.log('This wizard will help you configure notification channels for security alerts.');

      const setupChoices = await inquirer.prompt([
        {
          type: 'checkbox',
          name: 'channels',
          message: 'Which notification channels would you like to set up?',
          choices: [
            { name: 'Slack - Send alerts to Slack channels', value: 'slack' },
            { name: 'PagerDuty - Create incidents for critical alerts', value: 'pagerduty' },
            { name: 'Email - Send email notifications (coming soon)', value: 'email', disabled: true },
            { name: 'Webhook - Custom webhook integration', value: 'webhook', disabled: true }
          ],
          validate: (answer) => {
            if (answer.length < 1) {
              return 'You must choose at least one notification channel.';
            }
            return true;
          }
        }
      ]);

      let results: any = {
        channels: setupChoices.channels,
        configurations: {}
      };

      // Configure Slack
      if (setupChoices.channels.includes('slack')) {
        const slackConfig = await this.setupSlackInteractive();
        results.configurations.slack = slackConfig;
      }

      // Configure PagerDuty
      if (setupChoices.channels.includes('pagerduty')) {
        const pagerdutyConfig = await this.setupPagerDutyInteractive();
        results.configurations.pagerduty = pagerdutyConfig;
      }

      // Save configuration
      await this.saveConfigurations(results.configurations);

      // Test notifications if requested
      const testChoice = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'testNotifications',
          message: 'Would you like to test the notification channels now?',
          default: true
        }
      ]);

      if (testChoice.testNotifications) {
        for (const channel of setupChoices.channels) {
          try {
            const testResult = await this.testChannel(channel);
            if (testResult.success) {
              console.log(`✅ ${channel} test successful`);
            } else {
              console.log(`❌ ${channel} test failed: ${testResult.error}`);
            }
          } catch (error) {
            console.log(`❌ ${channel} test failed: ${error}`);
          }
        }
      }

      return this.createSuccessResult({
        message: 'Notification setup completed successfully!',
        configured_channels: setupChoices.channels,
        configurations: results.configurations,
        next_steps: [
          'Start monitoring with: a2a monitor',
          'Test notifications with: a2a query "test slack notification"',
          'Check status with: a2a status --component notifications'
        ]
      });

    } catch (error) {
      return this.createErrorResult(`Interactive setup failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async setupSlackInteractive(): Promise<any> {
    console.log('\\n📱 Setting up Slack notifications...');
    console.log('To get your Slack webhook URL:');
    console.log('1. Go to https://api.slack.com/apps');
    console.log('2. Create a new app or select existing app');
    console.log('3. Enable "Incoming Webhooks"');
    console.log('4. Add webhook to workspace and copy the URL');

    const slackQuestions = await inquirer.prompt([
      {
        type: 'input',
        name: 'webhookUrl',
        message: 'Enter your Slack webhook URL:',
        validate: (input) => {
          if (!input || !input.startsWith('https://hooks.slack.com/')) {
            return 'Please enter a valid Slack webhook URL (starts with https://hooks.slack.com/)';
          }
          return true;
        }
      },
      {
        type: 'input',
        name: 'channel',
        message: 'Enter the Slack channel for alerts (e.g., #security-alerts):',
        default: '#security-alerts',
        validate: (input) => {
          if (!input.startsWith('#')) {
            return 'Channel name should start with # (e.g., #security-alerts)';
          }
          return true;
        }
      },
      {
        type: 'input',
        name: 'username',
        message: 'Bot username for notifications:',
        default: 'Falco Security Bot'
      },
      {
        type: 'list',
        name: 'severityLevel',
        message: 'Send Slack notifications for which severity levels?',
        choices: [
          { name: 'Critical only', value: 'critical' },
          { name: 'High and Critical', value: 'high' },
          { name: 'Medium, High, and Critical', value: 'medium' },
          { name: 'All severity levels', value: 'all' }
        ],
        default: 'medium'
      }
    ]);

    return {
      enabled: true,
      webhookUrl: slackQuestions.webhookUrl,
      channel: slackQuestions.channel,
      username: slackQuestions.username,
      iconEmoji: ':shield:',
      severityLevel: slackQuestions.severityLevel
    };
  }

  private async setupPagerDutyInteractive(): Promise<any> {
    console.log('\\n📟 Setting up PagerDuty integration...');
    console.log('To get your PagerDuty integration key:');
    console.log('1. Go to your PagerDuty dashboard');
    console.log('2. Navigate to Services > Service Directory');
    console.log('3. Select your service or create a new one');
    console.log('4. Go to Integrations tab and add "Events API v2" integration');
    console.log('5. Copy the Integration Key');

    const pagerdutyQuestions = await inquirer.prompt([
      {
        type: 'input',
        name: 'apiKey',
        message: 'Enter your PagerDuty Integration Key:',
        validate: (input) => {
          if (!input || input.length < 10) {
            return 'Please enter a valid PagerDuty integration key';
          }
          return true;
        }
      },
      {
        type: 'list',
        name: 'severityLevel',
        message: 'Create PagerDuty incidents for which severity levels?',
        choices: [
          { name: 'Critical only', value: 'critical' },
          { name: 'High and Critical', value: 'high' }
        ],
        default: 'critical'
      },
      {
        type: 'confirm',
        name: 'autoResolve',
        message: 'Automatically resolve incidents when alerts are cleared?',
        default: true
      }
    ]);

    return {
      enabled: true,
      apiKey: pagerdutyQuestions.apiKey,
      serviceKey: pagerdutyQuestions.apiKey, // For backwards compatibility
      severityLevel: pagerdutyQuestions.severityLevel,
      autoResolve: pagerdutyQuestions.autoResolve
    };
  }

  private async setupNotifications(params: any): Promise<ToolResult> {
    const { channel, webhookUrl, slackChannel, pagerdutyApiKey, enabled = true } = params;

    if (!channel) {
      return this.createErrorResult('Channel parameter is required for setup');
    }

    const config = await this.configManager.getConfig();
    
    switch (channel) {
      case 'slack':
        if (!webhookUrl) {
          return this.createErrorResult('webhookUrl is required for Slack setup');
        }
        
        config.notifications.slack = {
          enabled,
          webhookUrl,
          channel: slackChannel || '#security-alerts',
          username: 'Falco Security Bot',
          iconEmoji: ':shield:'
        };
        break;

      case 'pagerduty':
        if (!pagerdutyApiKey) {
          return this.createErrorResult('pagerdutyApiKey is required for PagerDuty setup');
        }
        
        config.notifications.pagerduty = {
          enabled,
          apiKey: pagerdutyApiKey,
          serviceKey: pagerdutyApiKey
        };
        break;

      default:
        return this.createErrorResult(`Unsupported channel: ${channel}`);
    }

    await this.configManager.saveConfig(config);

    return this.createSuccessResult({
      message: `${channel} notifications configured successfully`,
      channel,
      enabled,
      next_steps: [
        `Test the configuration: a2a query "test ${channel} notification"`,
        'Start monitoring: a2a monitor',
        'Check status: a2a status --component notifications'
      ]
    });
  }

  private async configureChannel(channel: string, params: any): Promise<ToolResult> {
    if (!channel) {
      return this.createErrorResult('Channel parameter is required');
    }

    return await this.setupNotifications(params);
  }

  private async enableChannel(channel: string, enabled: boolean): Promise<ToolResult> {
    if (!channel) {
      return this.createErrorResult('Channel parameter is required');
    }

    const config = await this.configManager.getConfig();
    
    if (channel === 'all') {
      config.notifications.slack.enabled = enabled;
      config.notifications.pagerduty.enabled = enabled;
    } else if (config.notifications[channel as keyof typeof config.notifications]) {
      (config.notifications[channel as keyof typeof config.notifications] as any).enabled = enabled;
    } else {
      return this.createErrorResult(`Channel '${channel}' not found in configuration`);
    }

    await this.configManager.saveConfig(config);

    return this.createSuccessResult({
      message: `${channel} notifications ${enabled ? 'enabled' : 'disabled'}`,
      channel,
      enabled
    });
  }

  private async testChannel(channel?: string, testMessage?: string): Promise<ToolResult> {
    const config = await this.configManager.getConfig();
    const channels = channel && channel !== 'all' ? [channel] : ['slack', 'pagerduty'];
    const results: any = {};

    for (const ch of channels) {
      try {
        const channelConfig = config.notifications[ch as keyof typeof config.notifications];
        if (!channelConfig || !(channelConfig as any).enabled) {
          results[ch] = { success: false, error: 'Channel not configured or disabled' };
          continue;
        }

        // Import the appropriate channel class and test it
        if (ch === 'slack') {
          const { SlackChannel } = await import('@core/notifications/SlackChannel');
          const slackChannel = new SlackChannel(channelConfig as any);
          const success = await slackChannel.test!();
          results[ch] = { success, message: success ? 'Test message sent successfully' : 'Test failed' };
        } else if (ch === 'pagerduty') {
          const { PagerDutyChannel } = await import('@core/notifications/PagerDutyChannel');
          const pagerdutyChannel = new PagerDutyChannel(channelConfig as any);
          const success = await pagerdutyChannel.test!();
          results[ch] = { success, message: success ? 'Test incident created successfully' : 'Test failed' };
        }
      } catch (error) {
        results[ch] = { success: false, error: error instanceof Error ? error.message : 'Unknown error' };
      }
    }

    const successCount = Object.values(results).filter((r: any) => r.success).length;
    const totalCount = Object.keys(results).length;

    return this.createSuccessResult({
      message: `Notification test completed: ${successCount}/${totalCount} channels successful`,
      results,
      test_message: testMessage || 'Default test message',
      timestamp: new Date().toISOString()
    });
  }

  private async listChannels(): Promise<ToolResult> {
    const config = await this.configManager.getConfig();
    
    const channels = {
      slack: {
        enabled: config.notifications.slack.enabled,
        configured: !!config.notifications.slack.webhookUrl,
        channel: config.notifications.slack.channel || 'Not set',
        status: config.notifications.slack.enabled && config.notifications.slack.webhookUrl ? 'Ready' : 'Needs configuration'
      },
      pagerduty: {
        enabled: config.notifications.pagerduty.enabled,
        configured: !!config.notifications.pagerduty.apiKey,
        status: config.notifications.pagerduty.enabled && config.notifications.pagerduty.apiKey ? 'Ready' : 'Needs configuration'
      }
    };

    const summary = {
      total_channels: Object.keys(channels).length,
      enabled_channels: Object.values(channels).filter(ch => ch.enabled).length,
      configured_channels: Object.values(channels).filter(ch => ch.configured).length
    };

    return this.createSuccessResult({
      message: 'Notification channels status',
      summary,
      channels,
      recommendations: this.generateRecommendations(channels)
    });
  }

  private async updateChannel(channel: string, params: any): Promise<ToolResult> {
    if (!channel) {
      return this.createErrorResult('Channel parameter is required for update');
    }

    return await this.setupNotifications(params);
  }

  private async removeChannel(channel: string): Promise<ToolResult> {
    if (!channel) {
      return this.createErrorResult('Channel parameter is required for removal');
    }

    const config = await this.configManager.getConfig();
    
    if (channel === 'all') {
      config.notifications.slack.enabled = false;
      config.notifications.slack.webhookUrl = '';
      config.notifications.pagerduty.enabled = false;
      config.notifications.pagerduty.apiKey = '';
    } else if (config.notifications[channel as keyof typeof config.notifications]) {
      const channelConfig = config.notifications[channel as keyof typeof config.notifications] as any;
      channelConfig.enabled = false;
      if (channel === 'slack') {
        channelConfig.webhookUrl = '';
      } else if (channel === 'pagerduty') {
        channelConfig.apiKey = '';
      }
    } else {
      return this.createErrorResult(`Channel '${channel}' not found in configuration`);
    }

    await this.configManager.saveConfig(config);

    return this.createSuccessResult({
      message: `${channel} notifications removed successfully`,
      channel,
      status: 'disabled'
    });
  }

  private async saveConfigurations(configurations: any): Promise<void> {
    const config = await this.configManager.getConfig();
    
    if (configurations.slack) {
      config.notifications.slack = { ...config.notifications.slack, ...configurations.slack };
    }
    
    if (configurations.pagerduty) {
      config.notifications.pagerduty = { ...config.notifications.pagerduty, ...configurations.pagerduty };
    }

    await this.configManager.saveConfig(config);
  }

  private generateRecommendations(channels: any): string[] {
    const recommendations: string[] = [];

    if (!channels.slack.configured && !channels.pagerduty.configured) {
      recommendations.push('Set up at least one notification channel to receive security alerts');
    }

    if (channels.slack.configured && !channels.slack.enabled) {
      recommendations.push('Enable Slack notifications to receive alerts in your team channel');
    }

    if (channels.pagerduty.configured && !channels.pagerduty.enabled) {
      recommendations.push('Enable PagerDuty integration for critical incident management');
    }

    if (!channels.slack.configured) {
      recommendations.push('Configure Slack for team-wide security alert visibility');
    }

    if (!channels.pagerduty.configured) {
      recommendations.push('Set up PagerDuty for critical incident escalation and on-call management');
    }

    return recommendations;
  }
}