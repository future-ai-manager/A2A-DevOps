import { BaseTool } from '@mcp-servers/base/Tool';
import { ToolResult, MonitoringMetric } from '@core/types';
import axios from 'axios';

export class QueryMetricsTool extends BaseTool {
  readonly name = 'query_metrics';
  readonly description = 'Query metrics from Prometheus using PromQL';
  readonly inputSchema = {
    type: 'object' as const,
    properties: {
      query: {
        type: 'string',
        description: 'PromQL query to execute',
        examples: [
          'up',
          'rate(http_requests_total[5m])',
          'container_memory_usage_bytes{container!="POD"}',
          'cpu_usage_percent',
          'disk_free_bytes / disk_total_bytes * 100'
        ]
      },
      timeRange: {
        type: 'string',
        description: 'Time range for query (e.g., "5m", "1h", "1d")',
        default: '5m'
      },
      step: {
        type: 'string',
        description: 'Query resolution step (e.g., "15s", "1m")',
        default: '15s'
      },
      format: {
        type: 'string',
        enum: ['instant', 'range', 'both'],
        description: 'Query format - instant for current values, range for time series',
        default: 'instant'
      },
      prometheusUrl: {
        type: 'string',
        description: 'Prometheus server URL (overrides default)',
        format: 'uri'
      },
      maxDataPoints: {
        type: 'number',
        description: 'Maximum number of data points to return',
        default: 1000,
        minimum: 1,
        maximum: 10000
      }
    },
    required: ['query']
  };

  private defaultPrometheusUrl = 'http://localhost:9090';

  async execute(params: any): Promise<ToolResult> {
    if (!this.validateParams(params)) {
      return this.createErrorResult('Invalid parameters provided');
    }

    try {
      const {
        query,
        timeRange = '5m',
        step = '15s',
        format = 'instant',
        prometheusUrl = this.defaultPrometheusUrl,
        maxDataPoints = 1000
      } = params;

      // Validate PromQL query
      if (!this.isValidPromQLQuery(query)) {
        return this.createErrorResult('Invalid PromQL query syntax');
      }

      // Check Prometheus connectivity
      const isConnected = await this.checkPrometheusConnection(prometheusUrl);
      if (!isConnected) {
        return this.createErrorResult(`Cannot connect to Prometheus at ${prometheusUrl}. Please check the server is running and accessible.`);
      }

      let results: any = {};

      // Execute instant query if requested
      if (format === 'instant' || format === 'both') {
        const instantResult = await this.executeInstantQuery(query, prometheusUrl);
        results.instant = {
          query,
          timestamp: instantResult.timestamp,
          metrics: this.parseMetricsResult(instantResult.data),
          summary: this.generateMetricsSummary(instantResult.data)
        };
      }

      // Execute range query if requested
      if (format === 'range' || format === 'both') {
        const rangeResult = await this.executeRangeQuery(query, timeRange, step, prometheusUrl, maxDataPoints);
        results.range = {
          query,
          timeRange,
          step,
          dataPoints: rangeResult.data.length,
          metrics: this.parseTimeSeriesResult(rangeResult.data),
          summary: this.generateTimeSeriesSummary(rangeResult.data)
        };
      }

      // Generate insights and recommendations
      const insights = this.generateMetricsInsights(results, query);

      return this.createSuccessResult({
        query,
        format,
        timestamp: new Date().toISOString(),
        prometheusUrl,
        results,
        insights,
        metadata: {
          executionTime: Date.now(),
          queryValidation: 'passed',
          dataPointsReturned: this.countDataPoints(results)
        }
      });

    } catch (error) {
      return this.createErrorResult(`Failed to query metrics: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private isValidPromQLQuery(query: string): boolean {
    // Basic PromQL validation
    if (!query || query.trim().length === 0) return false;
    
    // Check for basic PromQL patterns
    const promqlPatterns = [
      /^[a-zA-Z_:][a-zA-Z0-9_:]*/, // Metric name
      /\{[^}]*\}/, // Label selector
      /\[[0-9]+[smhdwy]\]/, // Time range
      /by\s*\([^)]*\)/, // Aggregation by
      /without\s*\([^)]*\)/, // Aggregation without
      /(sum|avg|min|max|count|rate|increase|irate)\s*\(/, // Functions
    ];

    // At least one pattern should match for a valid query
    return promqlPatterns.some(pattern => pattern.test(query));
  }

  private async checkPrometheusConnection(prometheusUrl: string): Promise<boolean> {
    try {
      const response = await axios.get(`${prometheusUrl}/api/v1/query`, {
        params: { query: 'up' },
        timeout: 5000
      });
      return response.status === 200 && response.data.status === 'success';
    } catch (error) {
      // Try alternative endpoint
      try {
        const response = await axios.get(`${prometheusUrl}/-/healthy`, { timeout: 5000 });
        return response.status === 200;
      } catch {
        return false;
      }
    }
  }

  private async executeInstantQuery(query: string, prometheusUrl: string): Promise<any> {
    try {
      const response = await axios.get(`${prometheusUrl}/api/v1/query`, {
        params: { query },
        timeout: 30000
      });

      if (response.data.status !== 'success') {
        throw new Error(`Prometheus query failed: ${response.data.error || 'Unknown error'}`);
      }

      return {
        timestamp: Date.now(),
        data: response.data.data.result
      };

    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.code === 'ECONNREFUSED') {
          throw new Error('Connection refused - Prometheus server may not be running');
        } else if (error.response?.status === 422) {
          throw new Error('Invalid PromQL query syntax');
        }
      }
      throw error;
    }
  }

  private async executeRangeQuery(
    query: string,
    timeRange: string,
    step: string,
    prometheusUrl: string,
    maxDataPoints: number
  ): Promise<any> {
    try {
      const endTime = Math.floor(Date.now() / 1000);
      const startTime = endTime - this.parseTimeRange(timeRange);

      const response = await axios.get(`${prometheusUrl}/api/v1/query_range`, {
        params: {
          query,
          start: startTime,
          end: endTime,
          step
        },
        timeout: 60000
      });

      if (response.data.status !== 'success') {
        throw new Error(`Prometheus range query failed: ${response.data.error || 'Unknown error'}`);
      }

      let data = response.data.data.result;

      // Limit data points if necessary
      if (this.countTimeSeriesDataPoints(data) > maxDataPoints) {
        data = this.limitDataPoints(data, maxDataPoints);
      }

      return {
        data,
        startTime,
        endTime,
        step
      };

    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.code === 'ECONNREFUSED') {
          throw new Error('Connection refused - Prometheus server may not be running');
        } else if (error.response?.status === 422) {
          throw new Error('Invalid PromQL query or time range syntax');
        }
      }
      throw error;
    }
  }

  private parseTimeRange(timeRange: string): number {
    const match = timeRange.match(/^(\d+)([smhdw])$/);
    if (!match) return 300; // Default 5 minutes

    const [, value, unit] = match;
    const numValue = parseInt(value);

    switch (unit) {
      case 's': return numValue;
      case 'm': return numValue * 60;
      case 'h': return numValue * 3600;
      case 'd': return numValue * 86400;
      case 'w': return numValue * 604800;
      default: return 300;
    }
  }

  private parseMetricsResult(data: any[]): MonitoringMetric[] {
    const metrics: MonitoringMetric[] = [];

    for (const item of data) {
      const metric: MonitoringMetric = {
        name: item.metric.__name__ || 'unknown',
        value: parseFloat(item.value[1]),
        timestamp: parseInt(item.value[0]) * 1000,
        labels: { ...item.metric },
        unit: this.inferUnit(item.metric.__name__ || '')
      };

      delete metric.labels.__name__;
      metrics.push(metric);
    }

    return metrics.sort((a, b) => b.timestamp - a.timestamp);
  }

  private parseTimeSeriesResult(data: any[]): any[] {
    const series = [];

    for (const item of data) {
      const seriesData = {
        metric: item.metric,
        name: item.metric.__name__ || 'unknown',
        labels: { ...item.metric },
        values: item.values.map(([timestamp, value]: [number, string]) => ({
          timestamp: parseInt(timestamp.toString()) * 1000,
          value: parseFloat(value)
        })),
        unit: this.inferUnit(item.metric.__name__ || '')
      };

      delete seriesData.labels.__name__;
      series.push(seriesData);
    }

    return series;
  }

  private inferUnit(metricName: string): string {
    const metricLower = metricName.toLowerCase();
    
    if (metricLower.includes('bytes')) return 'bytes';
    if (metricLower.includes('seconds') || metricLower.includes('duration')) return 'seconds';
    if (metricLower.includes('percent') || metricLower.includes('ratio')) return '%';
    if (metricLower.includes('rate') || metricLower.includes('per_second')) return '/s';
    if (metricLower.includes('count') || metricLower.includes('total')) return 'count';
    if (metricLower.includes('cpu')) return '%';
    if (metricLower.includes('memory')) return 'bytes';
    if (metricLower.includes('disk')) return 'bytes';
    if (metricLower.includes('network')) return 'bytes';
    
    return '';
  }

  private generateMetricsSummary(data: any[]): any {
    if (!data || data.length === 0) {
      return { totalMetrics: 0, summary: 'No metrics found' };
    }

    const values = data.map((item: any) => parseFloat(item.value[1])).filter(v => !isNaN(v));
    
    if (values.length === 0) {
      return { totalMetrics: data.length, summary: 'No numeric values found' };
    }

    const summary = {
      totalMetrics: data.length,
      numericValues: values.length,
      min: Math.min(...values),
      max: Math.max(...values),
      avg: values.reduce((sum, val) => sum + val, 0) / values.length,
      uniqueMetricNames: [...new Set(data.map((item: any) => item.metric.__name__))].length
    };

    return summary;
  }

  private generateTimeSeriesSummary(data: any[]): any {
    if (!data || data.length === 0) {
      return { totalSeries: 0, summary: 'No time series data found' };
    }

    const totalDataPoints = data.reduce((sum, series) => sum + (series.values?.length || 0), 0);
    const timeRanges = data
      .filter(series => series.values && series.values.length > 1)
      .map(series => ({
        start: series.values[0][0],
        end: series.values[series.values.length - 1][0]
      }));

    const summary = {
      totalSeries: data.length,
      totalDataPoints,
      averagePointsPerSeries: data.length > 0 ? Math.round(totalDataPoints / data.length) : 0,
      uniqueMetricNames: [...new Set(data.map((series: any) => series.metric.__name__))].length,
      timeRange: timeRanges.length > 0 ? {
        start: Math.min(...timeRanges.map(tr => tr.start)),
        end: Math.max(...timeRanges.map(tr => tr.end))
      } : null
    };

    return summary;
  }

  private generateMetricsInsights(results: any, query: string): string[] {
    const insights: string[] = [];

    // Analyze instant results
    if (results.instant) {
      const { metrics, summary } = results.instant;
      
      if (summary.totalMetrics === 0) {
        insights.push('⚠️ Query returned no results - check metric names and labels');
      } else if (summary.totalMetrics > 100) {
        insights.push('📊 Large result set - consider adding label filters to narrow down results');
      }

      // Check for concerning values
      if (query.toLowerCase().includes('cpu') && summary.max > 90) {
        insights.push('🚨 High CPU usage detected (>90%) - investigate resource constraints');
      }

      if (query.toLowerCase().includes('memory') && summary.max > 0.9) {
        insights.push('🚨 High memory usage detected (>90%) - check for memory leaks');
      }

      if (query.toLowerCase().includes('up') && summary.min < 1) {
        insights.push('❌ Service availability issues detected - some targets are down');
      }
    }

    // Analyze range results
    if (results.range) {
      const { summary } = results.range;
      
      if (summary.totalSeries > 0 && summary.averagePointsPerSeries < 5) {
        insights.push('📈 Limited time series data - consider increasing time range or decreasing step size');
      }

      if (summary.totalDataPoints > 5000) {
        insights.push('⏰ Large time series dataset - consider reducing time range or increasing step size for better performance');
      }
    }

    // Query-specific insights
    if (query.includes('rate(') && !query.includes('[')) {
      insights.push('💡 Rate functions require a time range (e.g., rate(metric[5m]))');
    }

    if (query.includes('increase(') && !query.includes('[')) {
      insights.push('💡 Increase functions require a time range (e.g., increase(metric[1h]))');
    }

    return insights.slice(0, 5); // Limit to 5 insights
  }

  private countDataPoints(results: any): number {
    let count = 0;
    
    if (results.instant) {
      count += results.instant.metrics.length;
    }
    
    if (results.range) {
      count += results.range.summary.totalDataPoints;
    }
    
    return count;
  }

  private countTimeSeriesDataPoints(data: any[]): number {
    return data.reduce((sum, series) => sum + (series.values?.length || 0), 0);
  }

  private limitDataPoints(data: any[], maxDataPoints: number): any[] {
    // Simple implementation: keep first series and limit points
    // In production, would use more sophisticated sampling
    const limited = [...data];
    let totalPoints = this.countTimeSeriesDataPoints(limited);
    
    while (totalPoints > maxDataPoints && limited.length > 0) {
      // Reduce points by sampling every nth point
      for (const series of limited) {
        if (series.values && series.values.length > 2) {
          const step = Math.max(2, Math.ceil(series.values.length / (maxDataPoints / limited.length)));
          series.values = series.values.filter((_: any, index: number) => index % step === 0);
        }
      }
      totalPoints = this.countTimeSeriesDataPoints(limited);
    }
    
    return limited;
  }
}