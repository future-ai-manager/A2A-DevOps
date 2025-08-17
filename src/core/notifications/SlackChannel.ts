import axios from 'axios';
import { NotificationChannel, FormattedAlert, SlackConfig } from './types';
import { Logger } from '../../cli/utils/logger';

export class SlackChannel implements NotificationChannel {
  private logger = Logger.getInstance();

  constructor(private config: SlackConfig) {}

  async send(alert: FormattedAlert): Promise<void> {
    const message = this.formatSlackMessage(alert);
    
    try {
      const response = await axios.post(this.config.webhookUrl, message, {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 10000
      });

      if (response.status !== 200) {
        throw new Error(`Slack API returned status ${response.status}`);
      }

      this.logger.debug(`Slack message sent successfully for alert: ${alert.id}`);
    } catch (error) {
      this.logger.error(`Failed to send Slack message: ${error}`);
      throw error;
    }
  }

  private formatSlackMessage(alert: FormattedAlert): any {
    const color = this.getSeverityColor(alert.severity);
    const emoji = this.getSeverityEmoji(alert.severity);

    return {
      channel: this.config.channel,
      username: this.config.username || 'Falco Security Bot',
      icon_emoji: this.config.iconEmoji || emoji,
      text: `${emoji} *${alert.severity.toUpperCase()}* Security Alert`,
      attachments: [
        {
          color: color,
          title: alert.title,
          text: alert.summary,
          fields: [
            {
              title: 'Rule',
              value: alert.rule,
              short: true
            },
            {
              title: 'Source',
              value: alert.source,
              short: true
            },
            {
              title: 'Severity',
              value: alert.severity.toUpperCase(),
              short: true
            },
            {
              title: 'Timestamp',
              value: new Date(alert.timestamp).toLocaleString(),
              short: true
            }
          ],
          actions: alert.actions ? alert.actions.map(action => ({
            type: 'button',
            text: action.text,
            url: action.url
          })) : undefined,
          footer: 'A2A Falco Security Monitor',
          footer_icon: 'https://falco.org/img/falco-logo.png',
          ts: Math.floor(new Date(alert.timestamp).getTime() / 1000)
        }
      ]
    };
  }

  private getSeverityColor(severity: string): string {
    switch (severity) {
      case 'critical': return '#FF0000';
      case 'high': return '#FF8800';
      case 'medium': return '#FFAA00';
      case 'low': return '#36A64F';
      default: return '#808080';
    }
  }

  private getSeverityEmoji(severity: string): string {
    switch (severity) {
      case 'critical': return ':rotating_light:';
      case 'high': return ':warning:';
      case 'medium': return ':exclamation:';
      case 'low': return ':information_source:';
      default: return ':grey_question:';
    }
  }

  async test(): Promise<boolean> {
    const testMessage = {
      channel: this.config.channel,
      username: this.config.username || 'Falco Security Bot',
      icon_emoji: ':white_check_mark:',
      text: 'Test message from A2A Falco Security Monitor',
      attachments: [
        {
          color: '#36A64F',
          title: 'Connection Test',
          text: 'If you see this message, your Slack integration is working correctly!',
          footer: 'A2A Falco Security Monitor',
          ts: Math.floor(Date.now() / 1000)
        }
      ]
    };

    try {
      const response = await axios.post(this.config.webhookUrl, testMessage, {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 10000
      });

      return response.status === 200;
    } catch (error) {
      this.logger.error(`Slack test failed: ${error}`);
      return false;
    }
  }
}