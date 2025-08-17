import { MCPServer } from '@mcp-servers/base/MCPServer';
import { AgentCapability } from '@core/types';
import { QueryMetricsTool } from './tools/query-metrics';
import { GetAlertsTool } from './tools/get-alerts';
import axios from 'axios';

export class PrometheusServer extends MCPServer {
  readonly name = 'prometheus';
  readonly capabilities: AgentCapability[] = [
    {
      domain: 'metrics',
      description: 'System and application metrics collection and analysis',
      keywords: [
        'metrics', 'cpu', 'memory', 'disk', 'network', 'performance',
        'prometheus', 'promql', 'monitoring', 'observability'
      ],
      priority: 1
    },
    {
      domain: 'alerting',
      description: 'Alert rule management and evaluation',
      keywords: [
        'alert', 'notification', 'threshold', 'slo', 'sli',
        'alertmanager', 'firing', 'pending', 'rules'
      ],
      priority: 2
    },
    {
      domain: 'monitoring',
      description: 'System health monitoring and trend analysis',
      keywords: [
        'monitor', 'health', 'uptime', 'availability', 'dashboard',
        'time series', 'trend', 'analysis', 'grafana'
      ],
      priority: 1
    }
  ];

  private prometheusUrl = 'http://localhost:9090';
  private alertmanagerUrl = 'http://localhost:9093';

  protected initializeTools(): void {
    // Register all Prometheus-specific tools
    this.registerTool(new QueryMetricsTool());
    this.registerTool(new GetAlertsTool());
  }

  protected async onStart(): Promise<void> {
    try {
      // Check if Prometheus is available
      const prometheusAvailable = await this.checkPrometheusConnection();
      const alertmanagerAvailable = await this.checkAlertmanagerConnection();
      
      if (!prometheusAvailable) {
        console.warn('Prometheus not detected. Some features may be limited to mock data.');
        this.emit('warning', {
          server: this.name,
          message: 'Prometheus server not detected. Install and configure Prometheus for full monitoring capabilities.'
        });
      }

      if (!alertmanagerAvailable) {
        console.warn('Alertmanager not detected. Alert features may be limited.');
        this.emit('warning', {
          server: this.name,
          message: 'Alertmanager not detected. Install and configure Alertmanager for alert management.'
        });
      }

      // Initialize connections
      await this.initializePrometheusConnection();

      console.log(`Prometheus MCP Server started successfully on port ${this.port || 'default'}`);
      
    } catch (error) {
      console.error(`Failed to start Prometheus MCP Server: ${error}`);
      throw error;
    }
  }

  protected async onStop(): Promise<void> {
    try {
      // Cleanup connections
      await this.cleanupConnections();
      console.log('Prometheus MCP Server stopped successfully');
    } catch (error) {
      console.error(`Error stopping Prometheus MCP Server: ${error}`);
      throw error;
    }
  }

  private async checkPrometheusConnection(): Promise<boolean> {
    try {
      const response = await axios.get(`${this.prometheusUrl}/api/v1/query`, {
        params: { query: 'up' },
        timeout: 5000
      });
      return response.status === 200 && response.data.status === 'success';
    } catch {
      try {
        // Try alternative health endpoint
        const response = await axios.get(`${this.prometheusUrl}/-/healthy`, { timeout: 5000 });
        return response.status === 200;
      } catch {
        return false;
      }
    }
  }

  private async checkAlertmanagerConnection(): Promise<boolean> {
    try {
      const response = await axios.get(`${this.alertmanagerUrl}/api/v1/status`, { timeout: 5000 });
      return response.status === 200;
    } catch {
      return false;
    }
  }

  private async initializePrometheusConnection(): Promise<void> {
    try {
      // Test basic connectivity
      const prometheusAvailable = await this.checkPrometheusConnection();
      if (prometheusAvailable) {
        // Get basic server info
        const buildInfo = await this.getPrometheusBuildInfo();
        this.emit('info', {
          server: this.name,
          message: `Connected to Prometheus ${buildInfo.version || 'unknown'}`
        });
      }

      const alertmanagerAvailable = await this.checkAlertmanagerConnection();
      if (alertmanagerAvailable) {
        // Get Alertmanager status
        const status = await this.getAlertmanagerStatus();
        this.emit('info', {
          server: this.name,
          message: `Connected to Alertmanager (uptime: ${status.uptime || 'unknown'})`
        });
      }

    } catch (error) {
      this.emit('warning', {
        server: this.name,
        message: `Failed to initialize connections: ${error}`
      });
    }
  }

  private async cleanupConnections(): Promise<void> {
    try {
      // Cleanup any active connections or resources
      this.emit('info', {
        server: this.name,
        message: 'Connections cleaned up'
      });

    } catch (error) {
      this.emit('warning', {
        server: this.name,
        message: `Warning during cleanup: ${error}`
      });
    }
  }

  private async getPrometheusBuildInfo(): Promise<any> {
    try {
      const response = await axios.get(`${this.prometheusUrl}/api/v1/query`, {
        params: { query: 'prometheus_build_info' },
        timeout: 5000
      });

      if (response.data.status === 'success' && response.data.data.result.length > 0) {
        const buildInfo = response.data.data.result[0].metric;
        return {
          version: buildInfo.version,
          branch: buildInfo.branch,
          goVersion: buildInfo.goversion
        };
      }
    } catch (error) {
      // Ignore errors - build info is not critical
    }
    return {};
  }

  private async getAlertmanagerStatus(): Promise<any> {
    try {
      const response = await axios.get(`${this.alertmanagerUrl}/api/v1/status`, { timeout: 5000 });
      return response.data.data;
    } catch (error) {
      return {};
    }
  }

  // Public methods for external access
  async queryMetrics(promqlQuery: string, options: any = {}): Promise<any> {
    try {
      const queryTool = this.tools.get('query_metrics');
      if (!queryTool) {
        throw new Error('Query metrics tool not available');
      }

      const result = await queryTool.execute({
        query: promqlQuery,
        prometheusUrl: this.prometheusUrl,
        ...options
      });

      if (!result.success) {
        throw new Error(result.error || 'Failed to query metrics');
      }

      return result.data;

    } catch (error) {
      throw new Error(`Failed to query metrics: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getActiveAlerts(options: any = {}): Promise<any> {
    try {
      const alertsTool = this.tools.get('get_alerts');
      if (!alertsTool) {
        throw new Error('Get alerts tool not available');
      }

      const result = await alertsTool.execute({
        action: 'list_active',
        prometheusUrl: this.prometheusUrl,
        alertmanagerUrl: this.alertmanagerUrl,
        ...options
      });

      if (!result.success) {
        throw new Error(result.error || 'Failed to get alerts');
      }

      return result.data;

    } catch (error) {
      throw new Error(`Failed to get alerts: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getSystemHealth(): Promise<any> {
    try {
      // Query common health metrics
      const healthQueries = [
        { name: 'uptime', query: 'up' },
        { name: 'cpu_usage', query: '100 - (avg by (instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)' },
        { name: 'memory_usage', query: '(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100' },
        { name: 'disk_usage', query: '100 - ((node_filesystem_avail_bytes{mountpoint="/"} * 100) / node_filesystem_size_bytes{mountpoint="/"})' }
      ];

      const healthData: any = {
        timestamp: new Date().toISOString(),
        overall_status: 'unknown',
        metrics: {}
      };

      for (const healthQuery of healthQueries) {
        try {
          const result = await this.queryMetrics(healthQuery.query, { format: 'instant' });
          if (result.results.instant && result.results.instant.metrics.length > 0) {
            healthData.metrics[healthQuery.name] = {
              value: result.results.instant.metrics[0].value,
              status: this.determineMetricStatus(healthQuery.name, result.results.instant.metrics[0].value),
              timestamp: result.results.instant.timestamp
            };
          }
        } catch (error) {
          healthData.metrics[healthQuery.name] = {
            status: 'error',
            error: error instanceof Error ? error.message : 'Unknown error'
          };
        }
      }

      // Determine overall status
      const metricStatuses = Object.values(healthData.metrics).map((m: any) => m.status);
      if (metricStatuses.includes('critical')) {
        healthData.overall_status = 'critical';
      } else if (metricStatuses.includes('warning')) {
        healthData.overall_status = 'warning';
      } else if (metricStatuses.every(status => status === 'ok')) {
        healthData.overall_status = 'healthy';
      }

      // Get active alerts
      try {
        const alerts = await this.getActiveAlerts({ state: 'firing', maxAlerts: 10 });
        healthData.active_alerts = alerts.summary.firingAlerts;
        healthData.critical_alerts = alerts.alerts ? alerts.alerts.filter((a: any) => a.severity === 'critical').length : 0;
      } catch (error) {
        healthData.alerts_error = error instanceof Error ? error.message : 'Unknown error';
      }

      return healthData;

    } catch (error) {
      throw new Error(`Failed to get system health: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private determineMetricStatus(metricName: string, value: number): string {
    switch (metricName) {
      case 'uptime':
        return value >= 1 ? 'ok' : 'critical';
      case 'cpu_usage':
        if (value >= 90) return 'critical';
        if (value >= 75) return 'warning';
        return 'ok';
      case 'memory_usage':
        if (value >= 95) return 'critical';
        if (value >= 80) return 'warning';
        return 'ok';
      case 'disk_usage':
        if (value >= 95) return 'critical';
        if (value >= 85) return 'warning';
        return 'ok';
      default:
        return 'unknown';
    }
  }

  async getMetricsSummary(): Promise<any> {
    try {
      // Get summary of available metrics
      const labelNamesResult = await this.queryMetrics('label_names()', { format: 'instant' });
      
      // Get some common metrics
      const commonMetrics = [
        'up',
        'node_cpu_seconds_total',
        'node_memory_MemTotal_bytes',
        'node_filesystem_size_bytes',
        'http_requests_total'
      ];

      const metricsInfo = [];
      for (const metric of commonMetrics) {
        try {
          const result = await this.queryMetrics(metric, { format: 'instant' });
          if (result.results.instant && result.results.instant.metrics.length > 0) {
            metricsInfo.push({
              name: metric,
              instances: result.results.instant.metrics.length,
              latest_value: result.results.instant.metrics[0].value,
              unit: this.inferMetricUnit(metric)
            });
          }
        } catch {
          // Skip metrics that are not available
        }
      }

      return {
        timestamp: new Date().toISOString(),
        prometheus_url: this.prometheusUrl,
        available_metrics: metricsInfo.length,
        metrics: metricsInfo,
        server_info: await this.getPrometheusBuildInfo()
      };

    } catch (error) {
      throw new Error(`Failed to get metrics summary: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private inferMetricUnit(metricName: string): string {
    if (metricName.includes('bytes')) return 'bytes';
    if (metricName.includes('seconds')) return 's';
    if (metricName.includes('total')) return 'count';
    if (metricName.includes('rate')) return '/s';
    return '';
  }

  // Health check method
  async healthCheck(): Promise<{ status: string; details: any }> {
    try {
      const prometheusAvailable = await this.checkPrometheusConnection();
      const alertmanagerAvailable = await this.checkAlertmanagerConnection();
      const toolsCount = this.tools.size;
      
      const status = {
        status: prometheusAvailable ? 'healthy' : 'degraded',
        details: {
          prometheusConnection: prometheusAvailable ? 'available' : 'not_available',
          alertmanagerConnection: alertmanagerAvailable ? 'available' : 'not_available',
          prometheusUrl: this.prometheusUrl,
          alertmanagerUrl: this.alertmanagerUrl,
          registeredTools: toolsCount,
          capabilities: this.capabilities.length,
          serverStatus: this.status,
          lastHealthCheck: new Date().toISOString()
        }
      };

      if (!prometheusAvailable) {
        status.details.warning = 'Prometheus not detected. Install and configure Prometheus for monitoring capabilities.';
      }

      if (!alertmanagerAvailable) {
        status.details.alerting_warning = 'Alertmanager not detected. Alert features may be limited.';
      }

      return status;

    } catch (error) {
      return {
        status: 'unhealthy',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error',
          lastHealthCheck: new Date().toISOString()
        }
      };
    }
  }

  // Configuration methods
  setPrometheusUrl(url: string): void {
    this.prometheusUrl = url;
    this.emit('info', { server: this.name, message: `Prometheus URL updated to ${url}` });
  }

  setAlertmanagerUrl(url: string): void {
    this.alertmanagerUrl = url;
    this.emit('info', { server: this.name, message: `Alertmanager URL updated to ${url}` });
  }

  getConfiguration(): any {
    return {
      prometheusUrl: this.prometheusUrl,
      alertmanagerUrl: this.alertmanagerUrl,
      capabilities: this.capabilities,
      registeredTools: Array.from(this.tools.keys()),
      serverStatus: this.status
    };
  }

  // Method to get tool usage statistics
  getToolUsageStats(): any {
    const stats = {
      totalTools: this.tools.size,
      toolList: Array.from(this.tools.keys()),
      capabilities: this.capabilities.map(cap => ({
        domain: cap.domain,
        priority: cap.priority,
        keywordCount: cap.keywords.length
      })),
      serverUptime: this.isRunning ? 'running' : 'stopped',
      configuration: this.getConfiguration()
    };

    return stats;
  }
}