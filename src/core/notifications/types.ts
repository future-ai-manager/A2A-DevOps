export interface NotificationChannel {
  send(alert: FormattedAlert): Promise<void>;
  test?(): Promise<boolean>;
}

export interface FormattedAlert {
  id: string;
  title: string;
  summary: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  rule: string;
  source: string;
  timestamp: string;
  tags: string[];
  metadata: Record<string, any>;
  url?: string;
  actions?: Array<{ text: string; url: string }>;
}

export interface AlertDecision {
  send: boolean;
  channels?: string[];
  throttleKey?: string;
  throttleDuration?: number; // in milliseconds
}

export interface AlertRule {
  name: string;
  condition: (event: any) => boolean;
  channels: string[];
  throttleDuration?: number;
  priority?: number;
}

export interface SlackConfig {
  enabled: boolean;
  webhookUrl: string;
  channel?: string;
  username?: string;
  iconEmoji?: string;
}

export interface PagerDutyConfig {
  enabled: boolean;
  apiKey: string;
  serviceKey?: string;
  severity?: string;
}

export interface ChannelTestResult {
  channel: string;
  success: boolean;
  error?: string;
  responseTime?: number;
}