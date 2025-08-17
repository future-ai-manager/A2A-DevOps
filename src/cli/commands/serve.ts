import { Logger } from '../utils/logger';
import { ConfigManager } from '../utils/config';
import chalk from 'chalk';
import ora from 'ora';

const logger = Logger.getInstance();
const configManager = ConfigManager.getInstance();

export interface ServeOptions {
  port?: string;
  host?: string;
  apiOnly?: boolean;
  cors?: boolean;
  sslCert?: string;
  sslKey?: string;
}

export async function serveCommand(options: ServeOptions): Promise<void> {
  const spinner = ora('Starting A2A web server...').start();

  try {
    const {
      port = '3000',
      host = 'localhost',
      apiOnly = false,
      cors = false,
      sslCert,
      sslKey
    } = options;

    const config = await configManager.getConfig();
    const portNum = parseInt(port);
    const useSSL = sslCert && sslKey;

    spinner.text = 'Initializing web server...';

    // Import Express and related modules
    const express = await import('express');
    const { createServer } = await import('http');
    const { createServer: createHttpsServer } = useSSL ? await import('https') : { createServer: null };
    const { Server } = await import('socket.io');

    const app = express.default();
    
    // Configure middleware
    if (cors) {
      const corsMiddleware = await import('cors');
      app.use(corsMiddleware.default());
    }

    app.use(express.json());
    app.use(logger.createMiddleware());

    // API Routes
    await setupApiRoutes(app);

    // Static file serving (if not API-only)
    if (!apiOnly) {
      await setupStaticRoutes(app);
    }

    // Create HTTP/HTTPS server
    let server;
    if (useSSL && createHttpsServer) {
      const fs = await import('fs');
      const httpsOptions = {
        cert: fs.readFileSync(sslCert!),
        key: fs.readFileSync(sslKey!)
      };
      server = createHttpsServer(httpsOptions, app);
    } else {
      server = createServer(app);
    }

    // Setup WebSocket
    const io = new Server(server, {
      cors: cors ? { origin: "*" } : undefined
    });

    await setupWebSocket(io);

    // Start server
    await new Promise<void>((resolve, reject) => {
      server.listen(portNum, host, () => {
        resolve();
      }).on('error', reject);
    });

    spinner.succeed('A2A web server started successfully');

    const protocol = useSSL ? 'https' : 'http';
    const serverUrl = `${protocol}://${host}:${port}`;
    
    console.log(chalk.green('🌐 A2A Web Server Running'));
    console.log(chalk.blue('=' .repeat(40)));
    console.log(`📍 Server URL: ${chalk.cyan(serverUrl)}`);
    console.log(`🔧 Mode: ${apiOnly ? 'API Only' : 'Full Web UI'}`);
    console.log(`🔒 Security: ${useSSL ? 'HTTPS Enabled' : 'HTTP'}`);
    console.log(`🌍 CORS: ${cors ? 'Enabled' : 'Disabled'}`);
    console.log('');
    
    if (!apiOnly) {
      console.log(`🎯 Web UI: ${chalk.cyan(serverUrl)}`);
    }
    console.log(`📡 API Endpoint: ${chalk.cyan(`${serverUrl}/api`)}`);
    console.log(`🔌 WebSocket: ${chalk.cyan(`${serverUrl}/socket.io`)}`);
    console.log('');
    console.log(chalk.yellow('Press Ctrl+C to stop the server'));

    // Handle graceful shutdown
    process.on('SIGINT', () => {
      console.log(chalk.blue('\n🛑 Shutting down server gracefully...'));
      server.close(() => {
        console.log(chalk.blue('👋 Server stopped'));
        process.exit(0);
      });
    });

  } catch (error) {
    spinner.fail('Failed to start web server');
    logger.errorMessage(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    process.exit(1);
  }
}

async function setupApiRoutes(app: any): Promise<void> {
  const router = (await import('express')).Router();

  // Health check endpoint
  router.get('/health', (req, res) => {
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      version: '1.0.0'
    });
  });

  // Query endpoint
  router.post('/query', async (req, res) => {
    try {
      const { query, agent, format } = req.body;
      
      if (!query) {
        return res.status(400).json({ error: 'Query is required' });
      }

      // TODO: Integrate with actual query processing
      // For now, return a mock response
      const mockResponse = {
        query,
        agent: agent || 'auto-detected',
        timestamp: new Date().toISOString(),
        success: true,
        data: {
          message: `Processed query: ${query}`,
          agent_used: agent || 'general',
          confidence: 0.85
        }
      };

      res.json(mockResponse);
      
    } catch (error) {
      logger.error('API query error:', error);
      res.status(500).json({ 
        error: 'Internal server error',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Status endpoint
  router.get('/status', async (req, res) => {
    try {
      // TODO: Get actual system status
      const status = {
        timestamp: new Date().toISOString(),
        services: {
          falco: 'unknown',
          prometheus: 'unknown',
          claude_code: 'unknown'
        },
        agents: {
          falco: { status: 'available', tools: 3 },
          prometheus: { status: 'available', tools: 2 },
          general: { status: 'available', tools: 0 }
        },
        statistics: {
          total_queries: 0,
          successful_queries: 0,
          failed_queries: 0,
          uptime: process.uptime()
        }
      };

      res.json(status);
      
    } catch (error) {
      logger.error('API status error:', error);
      res.status(500).json({ error: 'Failed to get status' });
    }
  });

  // Security alerts endpoint
  router.get('/alerts', async (req, res) => {
    try {
      const { severity = 'all', limit = 50 } = req.query;
      
      // TODO: Get actual alerts from Falco
      const mockAlerts = Array.from({ length: Math.min(parseInt(limit as string), 10) }, (_, i) => ({
        id: `alert-${i + 1}`,
        timestamp: new Date(Date.now() - i * 60000).toISOString(),
        severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
        rule: 'Mock Security Rule',
        description: `Mock security alert #${i + 1}`,
        status: 'active'
      }));

      res.json({
        alerts: mockAlerts,
        total: mockAlerts.length,
        filters: { severity, limit }
      });
      
    } catch (error) {
      logger.error('API alerts error:', error);
      res.status(500).json({ error: 'Failed to get alerts' });
    }
  });

  // Metrics endpoint
  router.get('/metrics', async (req, res) => {
    try {
      const { query: promql, range = '5m' } = req.query;
      
      // TODO: Get actual metrics from Prometheus
      const mockMetrics = {
        timestamp: new Date().toISOString(),
        query: promql || 'up',
        range,
        metrics: [
          { name: 'up', value: 1, labels: { instance: 'localhost:9090' } },
          { name: 'cpu_usage', value: 45.2, labels: { instance: 'server-01' } },
          { name: 'memory_usage', value: 68.7, labels: { instance: 'server-01' } }
        ]
      };

      res.json(mockMetrics);
      
    } catch (error) {
      logger.error('API metrics error:', error);
      res.status(500).json({ error: 'Failed to get metrics' });
    }
  });

  app.use('/api', router);
}

async function setupStaticRoutes(app: any): Promise<void> {
  const path = await import('path');
  
  // Serve static files (would contain the web UI)
  // For now, serve a simple HTML page
  app.get('/', (req, res) => {
    res.send(generateDashboardHTML());
  });

  // API documentation
  app.get('/docs', (req, res) => {
    res.send(generateApiDocsHTML());
  });
}

async function setupWebSocket(io: any): Promise<void> {
  io.on('connection', (socket: any) => {
    logger.debug('Client connected to WebSocket');

    socket.on('subscribe', (channel: string) => {
      socket.join(channel);
      logger.debug(`Client subscribed to ${channel}`);
    });

    socket.on('unsubscribe', (channel: string) => {
      socket.leave(channel);
      logger.debug(`Client unsubscribed from ${channel}`);
    });

    socket.on('query', async (data: any) => {
      try {
        // TODO: Process query and emit response
        socket.emit('query-response', {
          id: data.id,
          success: true,
          data: { message: `Processed: ${data.query}` }
        });
      } catch (error) {
        socket.emit('query-response', {
          id: data.id,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    });

    socket.on('disconnect', () => {
      logger.debug('Client disconnected from WebSocket');
    });
  });

  // Simulate real-time events
  setInterval(() => {
    const mockEvent = {
      type: 'security-event',
      timestamp: new Date().toISOString(),
      severity: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)],
      message: 'Simulated security event'
    };
    io.to('events').emit('new-event', mockEvent);
  }, 30000); // Every 30 seconds
}

function generateDashboardHTML(): string {
  return `
<!DOCTYPE html>
<html>
<head>
    <title>A2A DevOps Platform</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .status { display: flex; align-items: center; gap: 10px; margin: 10px 0; }
        .status-ok { color: #10b981; }
        .status-warning { color: #f59e0b; }
        .status-error { color: #ef4444; }
        .btn { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #5a6fd8; }
        .code { background: #1f2937; color: #e5e7eb; padding: 15px; border-radius: 5px; font-family: 'Monaco', 'Courier New', monospace; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🤖 A2A DevOps Platform</h1>
            <p>Agent-to-Agent DevOps automation powered by AI</p>
        </div>

        <div class="grid">
            <div class="card">
                <h3>🔒 Security Status</h3>
                <div class="status">
                    <span class="status-ok">●</span>
                    <span>Falco Runtime Security: Active</span>
                </div>
                <div class="status">
                    <span class="status-warning">●</span>
                    <span>2 Medium Severity Alerts</span>
                </div>
                <a href="/api/alerts" class="btn">View Alerts</a>
            </div>

            <div class="card">
                <h3>📊 Monitoring</h3>
                <div class="status">
                    <span class="status-ok">●</span>
                    <span>Prometheus: Connected</span>
                </div>
                <div class="status">
                    <span class="status-ok">●</span>
                    <span>All Systems Healthy</span>
                </div>
                <a href="/api/metrics" class="btn">View Metrics</a>
            </div>

            <div class="card">
                <h3>🤖 AI Agents</h3>
                <div class="status">
                    <span class="status-ok">●</span>
                    <span>Falco Security Agent</span>
                </div>
                <div class="status">
                    <span class="status-ok">●</span>
                    <span>Prometheus Monitoring Agent</span>
                </div>
                <div class="status">
                    <span class="status-ok">●</span>
                    <span>General DevOps Agent</span>
                </div>
            </div>

            <div class="card">
                <h3>🚀 Quick Start</h3>
                <p>Try these commands:</p>
                <div class="code">
# Check security threats
a2a query "detect security threats"

# Check system metrics  
a2a query "show CPU and memory usage"

# Start real-time monitoring
a2a monitor --severity high
                </div>
            </div>

            <div class="card">
                <h3>📡 API Endpoints</h3>
                <ul>
                    <li><a href="/api/health">/api/health</a> - Health check</li>
                    <li><a href="/api/status">/api/status</a> - System status</li>
                    <li><a href="/api/alerts">/api/alerts</a> - Security alerts</li>
                    <li><a href="/api/metrics">/api/metrics</a> - System metrics</li>
                </ul>
                <a href="/docs" class="btn">API Documentation</a>
            </div>

            <div class="card">
                <h3>💡 Features</h3>
                <ul>
                    <li>🔍 Natural language query processing</li>
                    <li>🛡️ Runtime security monitoring with Falco</li>
                    <li>📈 Metrics collection with Prometheus</li>
                    <li>🤖 Intelligent agent routing</li>
                    <li>⚡ Real-time event streaming</li>
                    <li>🔧 RESTful API & WebSocket support</li>
                </ul>
            </div>
        </div>
    </div>

    <script>
        // Simple status refresh
        setInterval(() => {
            fetch('/api/health')
                .then(r => r.json())
                .then(data => console.log('Health check:', data))
                .catch(e => console.error('Health check failed:', e));
        }, 30000);
    </script>
</body>
</html>`;
}

function generateApiDocsHTML(): string {
  return `
<!DOCTYPE html>
<html>
<head>
    <title>A2A API Documentation</title>
    <meta charset="utf-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; line-height: 1.6; }
        .container { max-width: 1000px; margin: 0 auto; }
        .endpoint { background: #f8f9fa; padding: 20px; margin: 20px 0; border-left: 4px solid #007bff; }
        .method { background: #007bff; color: white; padding: 5px 10px; border-radius: 3px; font-weight: bold; }
        .method.post { background: #28a745; }
        .method.put { background: #ffc107; color: black; }
        .method.delete { background: #dc3545; }
        pre { background: #1f2937; color: #e5e7eb; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .back-btn { background: #6c757d; color: white; text-decoration: none; padding: 10px 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>A2A API Documentation</h1>
        <a href="/" class="back-btn">← Back to Dashboard</a>

        <div class="endpoint">
            <h3><span class="method">GET</span> /api/health</h3>
            <p>Health check endpoint to verify API availability.</p>
            <h4>Response:</h4>
            <pre>{
  "status": "ok",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "version": "1.0.0"
}</pre>
        </div>

        <div class="endpoint">
            <h3><span class="method post">POST</span> /api/query</h3>
            <p>Process natural language queries using AI-powered agent routing.</p>
            <h4>Request Body:</h4>
            <pre>{
  "query": "detect security threats in the last hour",
  "agent": "falco",  // optional
  "format": "json"   // optional
}</pre>
            <h4>Response:</h4>
            <pre>{
  "query": "detect security threats in the last hour",
  "agent": "falco",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "success": true,
  "data": { ... }
}</pre>
        </div>

        <div class="endpoint">
            <h3><span class="method">GET</span> /api/status</h3>
            <p>Get overall system status and agent health information.</p>
            <h4>Response:</h4>
            <pre>{
  "timestamp": "2024-01-01T00:00:00.000Z",
  "services": {
    "falco": "running",
    "prometheus": "running", 
    "claude_code": "available"
  },
  "agents": {
    "falco": { "status": "available", "tools": 3 },
    "prometheus": { "status": "available", "tools": 2 },
    "general": { "status": "available", "tools": 0 }
  },
  "statistics": {
    "total_queries": 42,
    "successful_queries": 40,
    "failed_queries": 2,
    "uptime": 3600
  }
}</pre>
        </div>

        <div class="endpoint">
            <h3><span class="method">GET</span> /api/alerts</h3>
            <p>Get active security alerts from Falco.</p>
            <h4>Query Parameters:</h4>
            <ul>
                <li><code>severity</code> - Filter by severity (low, medium, high, critical)</li>
                <li><code>limit</code> - Maximum number of alerts to return</li>
            </ul>
            <h4>Response:</h4>
            <pre>{
  "alerts": [
    {
      "id": "alert-1",
      "timestamp": "2024-01-01T00:00:00.000Z",
      "severity": "high",
      "rule": "Terminal shell in container",
      "description": "Shell spawned in container",
      "status": "active"
    }
  ],
  "total": 1,
  "filters": { "severity": "all", "limit": 50 }
}</pre>
        </div>

        <div class="endpoint">
            <h3><span class="method">GET</span> /api/metrics</h3>
            <p>Get system metrics from Prometheus.</p>
            <h4>Query Parameters:</h4>
            <ul>
                <li><code>query</code> - PromQL query string</li>
                <li><code>range</code> - Time range for metrics</li>
            </ul>
            <h4>Response:</h4>
            <pre>{
  "timestamp": "2024-01-01T00:00:00.000Z",
  "query": "up",
  "range": "5m",
  "metrics": [
    {
      "name": "up",
      "value": 1,
      "labels": { "instance": "localhost:9090" }
    }
  ]
}</pre>
        </div>

        <h2>WebSocket Events</h2>
        <p>Connect to <code>/socket.io</code> for real-time events:</p>
        
        <div class="endpoint">
            <h3>Event: new-event</h3>
            <p>Emitted when new security events are detected.</p>
            <pre>{
  "type": "security-event",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "severity": "medium",
  "message": "New security event detected"
}</pre>
        </div>

        <h2>Error Responses</h2>
        <p>All endpoints may return error responses in this format:</p>
        <pre>{
  "error": "Error description",
  "message": "Detailed error message",
  "timestamp": "2024-01-01T00:00:00.000Z"
}</pre>
    </div>
</body>
</html>`;
}