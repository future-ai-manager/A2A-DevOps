import { EventEmitter } from 'events';
import { Configuration, SecurityEvent } from '../types';
import { Logger } from '../../cli/utils/logger';
import { NotificationChannel, FormattedAlert, AlertDecision } from './types';
import { SlackChannel } from './SlackChannel';
import { PagerDutyChannel } from './PagerDutyChannel';
import { AlertPolicy } from './AlertPolicy';

export class NotificationManager extends EventEmitter {
  private channels: Map<string, NotificationChannel> = new Map();
  private alertPolicy: AlertPolicy;
  private throttleCache: Map<string, number> = new Map();
  private logger = Logger.getInstance();

  constructor(private config: Configuration['notifications']) {
    super();
    this.alertPolicy = new AlertPolicy();
    this.initializeChannels();
  }

  private initializeChannels(): void {
    try {
      if (this.config?.slack?.enabled && this.config.slack.webhookUrl) {
        this.channels.set('slack', new SlackChannel(this.config.slack));
        this.logger.info('Slack notification channel initialized');
      }

      if (this.config?.pagerduty?.enabled && this.config.pagerduty.apiKey) {
        this.channels.set('pagerduty', new PagerDutyChannel(this.config.pagerduty));
        this.logger.info('PagerDuty notification channel initialized');
      }

      if (this.channels.size === 0) {
        this.logger.warn('No notification channels configured');
      }
    } catch (error) {
      this.logger.error(`Failed to initialize notification channels: ${error}`);
    }
  }

  async sendAlert(event: SecurityEvent, forceChannels?: string[]): Promise<void> {
    try {
      const decision = this.alertPolicy.shouldAlert(event);
      
      if (!decision.send && !forceChannels) {
        this.logger.debug(`Alert suppressed by policy: ${event.rule}`);
        return;
      }

      const channels = forceChannels || decision.channels || ['slack'];
      const throttleKey = decision.throttleKey || `${event.rule}-${event.source}`;

      // Check throttling
      if (this.isThrottled(throttleKey, decision.throttleDuration)) {
        this.logger.debug(`Alert throttled: ${throttleKey}`);
        return;
      }

      const formattedAlert = this.formatAlert(event);
      const promises = channels.map(async (channelName) => {
        const channel = this.channels.get(channelName);
        if (channel) {
          try {
            await channel.send(formattedAlert);
            this.logger.info(`Alert sent to ${channelName}: ${event.rule}`);
          } catch (error) {
            this.logger.error(`Failed to send alert to ${channelName}: ${error}`);
          }
        } else {
          this.logger.warn(`Notification channel '${channelName}' not configured`);
        }
      });

      await Promise.all(promises);

      // Update throttle cache
      if (decision.throttleDuration) {
        this.throttleCache.set(throttleKey, Date.now());
      }

      this.emit('alertSent', { event, channels, timestamp: new Date().toISOString() });

    } catch (error) {
      this.logger.error(`Failed to send alert: ${error}`);
      this.emit('alertError', { event, error });
    }
  }

  private isThrottled(key: string, throttleDuration?: number): boolean {
    if (!throttleDuration) return false;
    
    const lastSent = this.throttleCache.get(key);
    if (!lastSent) return false;
    
    return (Date.now() - lastSent) < throttleDuration;
  }

  private formatAlert(event: SecurityEvent): FormattedAlert {
    return {
      id: event.id,
      title: `🚨 Security Alert: ${event.rule}`,
      summary: event.description,
      severity: event.severity,
      rule: event.rule,
      source: event.source,
      timestamp: event.timestamp,
      tags: event.tags,
      metadata: event.metadata,
      url: this.generateAlertUrl(event),
      actions: this.generateAlertActions(event)
    };
  }

  private generateAlertUrl(event: SecurityEvent): string {
    // Generate URL to alert details page
    return `https://your-dashboard.com/alerts/${event.id}`;
  }

  private generateAlertActions(event: SecurityEvent): Array<{ text: string; url: string }> {
    return [
      {
        text: 'View Details',
        url: this.generateAlertUrl(event)
      },
      {
        text: 'Investigate',
        url: `https://your-dashboard.com/investigate?rule=${encodeURIComponent(event.rule)}`
      }
    ];
  }

  async testChannel(channelName: string): Promise<boolean> {
    const channel = this.channels.get(channelName);
    if (!channel) {
      throw new Error(`Channel '${channelName}' not found`);
    }

    const testEvent: SecurityEvent = {
      id: 'test-' + Date.now(),
      timestamp: new Date().toISOString(),
      severity: 'low',
      rule: 'Test Alert',
      description: 'This is a test alert to verify channel configuration',
      source: 'notification-manager',
      tags: ['test'],
      metadata: { test: true }
    };

    try {
      await this.sendAlert(testEvent, [channelName]);
      return true;
    } catch (error) {
      this.logger.error(`Channel test failed for ${channelName}: ${error}`);
      return false;
    }
  }

  getChannelStatus(): Record<string, boolean> {
    const status: Record<string, boolean> = {};
    for (const [name] of this.channels) {
      status[name] = true; // In real implementation, check actual channel health
    }
    return status;
  }

  updateConfig(config: Configuration['notifications']): void {
    this.config = config;
    this.channels.clear();
    this.initializeChannels();
    this.emit('configUpdated', config);
  }

  // Clean up old throttle entries
  private cleanupThrottleCache(): void {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    for (const [key, timestamp] of this.throttleCache.entries()) {
      if (now - timestamp > maxAge) {
        this.throttleCache.delete(key);
      }
    }
  }

  // Start periodic cleanup
  startCleanup(): void {
    setInterval(() => this.cleanupThrottleCache(), 60 * 60 * 1000); // Every hour
  }

  stop(): void {
    this.channels.clear();
    this.throttleCache.clear();
    this.removeAllListeners();
  }
}