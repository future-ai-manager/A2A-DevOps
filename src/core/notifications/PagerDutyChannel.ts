import axios from 'axios';
import { NotificationChannel, FormattedAlert, PagerDutyConfig } from './types';
import { Logger } from '../../cli/utils/logger';

export class PagerDutyChannel implements NotificationChannel {
  private logger = Logger.getInstance();
  private readonly apiUrl = 'https://events.pagerduty.com/v2/enqueue';

  constructor(private config: PagerDutyConfig) {}

  async send(alert: FormattedAlert): Promise<void> {
    const payload = this.formatPagerDutyPayload(alert);
    
    try {
      const response = await axios.post(this.apiUrl, payload, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Token token=${this.config.apiKey}`
        },
        timeout: 10000
      });

      if (response.status !== 202) {
        throw new Error(`PagerDuty API returned status ${response.status}`);
      }

      this.logger.debug(`PagerDuty event sent successfully for alert: ${alert.id}`);
    } catch (error) {
      this.logger.error(`Failed to send PagerDuty event: ${error}`);
      throw error;
    }
  }

  private formatPagerDutyPayload(alert: FormattedAlert): any {
    const severity = this.mapSeverityToPagerDuty(alert.severity);
    
    return {
      routing_key: this.config.serviceKey || this.config.apiKey,
      event_action: 'trigger',
      dedup_key: `falco-${alert.rule}-${alert.source}`,
      payload: {
        summary: alert.title,
        source: alert.source,
        severity: severity,
        timestamp: alert.timestamp,
        component: 'falco',
        group: 'security',
        class: alert.rule,
        custom_details: {
          rule: alert.rule,
          description: alert.summary,
          tags: alert.tags.join(', '),
          metadata: alert.metadata,
          alert_id: alert.id
        }
      },
      client: 'A2A Falco Security Monitor',
      client_url: alert.url,
      links: alert.actions ? alert.actions.map(action => ({
        href: action.url,
        text: action.text
      })) : undefined
    };
  }

  private mapSeverityToPagerDuty(severity: string): string {
    switch (severity) {
      case 'critical': return 'critical';
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'info';
    }
  }

  async test(): Promise<boolean> {
    const testPayload = {
      routing_key: this.config.serviceKey || this.config.apiKey,
      event_action: 'trigger',
      dedup_key: `test-${Date.now()}`,
      payload: {
        summary: 'Test event from A2A Falco Security Monitor',
        source: 'notification-test',
        severity: 'info',
        timestamp: new Date().toISOString(),
        component: 'falco',
        group: 'security',
        class: 'test',
        custom_details: {
          test: true,
          message: 'This is a test event to verify PagerDuty integration'
        }
      },
      client: 'A2A Falco Security Monitor'
    };

    try {
      const response = await axios.post(this.apiUrl, testPayload, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Token token=${this.config.apiKey}`
        },
        timeout: 10000
      });

      return response.status === 202;
    } catch (error) {
      this.logger.error(`PagerDuty test failed: ${error}`);
      return false;
    }
  }
}