import { EventEmitter } from 'events';
import { MCPServer } from '@mcp-servers/base/MCPServer';
import { FalcoServer } from '@mcp-servers/falco/FalcoServer';
import { PrometheusServer } from '@mcp-servers/prometheus/PrometheusServer';
import { ServerConfig, ToolResult } from './types';
import { Logger } from '@cli/utils/logger';

const logger = Logger.getInstance();

export interface ServerInfo {
  name: string;
  status: 'stopped' | 'starting' | 'running' | 'stopping' | 'error';
  port?: number;
  startTime?: Date;
  error?: string;
  tools: number;
  capabilities: number;
}

export class MCPServerManager extends EventEmitter {
  private servers: Map<string, MCPServer> = new Map();
  private serverConfigs: Map<string, ServerConfig> = new Map();
  private serverInfo: Map<string, ServerInfo> = new Map();
  private healthCheckInterval?: NodeJS.Timeout;
  private isShuttingDown = false;

  constructor() {
    super();
    this.initializeDefaultServers();
  }

  private initializeDefaultServers(): void {
    // Register default server configurations
    this.serverConfigs.set('falco', {
      name: 'falco',
      command: 'falco-mcp-server',
      args: [],
      domain: 'security',
      capabilities: [
        {
          domain: 'security',
          description: 'Runtime security monitoring and threat detection',
          keywords: ['security', 'threat', 'vulnerability', 'malware', 'intrusion'],
          priority: 1
        }
      ]
    });

    this.serverConfigs.set('prometheus', {
      name: 'prometheus',
      command: 'prometheus-mcp-server',
      args: [],
      domain: 'monitoring',
      capabilities: [
        {
          domain: 'metrics',
          description: 'System and application metrics collection',
          keywords: ['metrics', 'cpu', 'memory', 'disk', 'network', 'performance'],
          priority: 1
        }
      ]
    });
  }

  async start(): Promise<void> {
    if (this.isShuttingDown) {
      throw new Error('Cannot start servers during shutdown');
    }

    logger.info('Starting MCP Server Manager...');

    try {
      // Create and start server instances
      await this.createServerInstances();
      await this.startAllServers();
      
      // Start health monitoring
      this.startHealthMonitoring();

      logger.success('MCP Server Manager started successfully');
      this.emit('started', { manager: 'MCPServerManager' });

    } catch (error) {
      logger.errorMessage(`Failed to start MCP Server Manager: ${error instanceof Error ? error.message : 'Unknown error'}`);
      await this.stop(); // Cleanup on failure
      throw error;
    }
  }

  async stop(): Promise<void> {
    if (this.isShuttingDown) {
      return; // Already shutting down
    }

    this.isShuttingDown = true;
    logger.info('Stopping MCP Server Manager...');

    try {
      // Stop health monitoring
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
        this.healthCheckInterval = undefined;
      }

      // Stop all servers in parallel
      const stopPromises = Array.from(this.servers.values()).map(async (server) => {
        try {
          await server.stop();
        } catch (error) {
          logger.warn(`Error stopping server ${server.name}: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      });

      await Promise.all(stopPromises);

      // Clear server collections
      this.servers.clear();
      this.serverInfo.clear();

      logger.success('MCP Server Manager stopped successfully');
      this.emit('stopped', { manager: 'MCPServerManager' });

    } catch (error) {
      logger.errorMessage(`Error during MCP Server Manager shutdown: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      this.isShuttingDown = false;
    }
  }

  private async createServerInstances(): Promise<void> {
    // Create Falco server instance
    const falcoServer = new FalcoServer();
    this.servers.set('falco', falcoServer);
    this.serverInfo.set('falco', {
      name: 'falco',
      status: 'stopped',
      tools: falcoServer.toolCount,
      capabilities: falcoServer.capabilities.length
    });

    // Create Prometheus server instance
    const prometheusServer = new PrometheusServer();
    this.servers.set('prometheus', prometheusServer);
    this.serverInfo.set('prometheus', {
      name: 'prometheus',
      status: 'stopped',
      tools: prometheusServer.toolCount,
      capabilities: prometheusServer.capabilities.length
    });

    // Set up event listeners
    this.setupServerEventListeners();
  }

  private setupServerEventListeners(): void {
    for (const [name, server] of this.servers) {
      server.on('started', (data) => {
        this.updateServerStatus(name, 'running', undefined, new Date());
        logger.info(`MCP Server '${name}' started successfully`);
        this.emit('serverStarted', { name, ...data });
      });

      server.on('stopped', (data) => {
        this.updateServerStatus(name, 'stopped');
        logger.info(`MCP Server '${name}' stopped`);
        this.emit('serverStopped', { name, ...data });
      });

      server.on('error', (error) => {
        this.updateServerStatus(name, 'error', error.message || 'Unknown error');
        logger.errorMessage(`MCP Server '${name}' error: ${error.message || 'Unknown error'}`);
        this.emit('serverError', { name, error });
      });

      server.on('warning', (warning) => {
        logger.warning(`MCP Server '${name}' warning: ${warning.message || 'Unknown warning'}`);
        this.emit('serverWarning', { name, warning });
      });
    }
  }

  private async startAllServers(): Promise<void> {
    const startPromises = Array.from(this.servers.entries()).map(async ([name, server]) => {
      try {
        this.updateServerStatus(name, 'starting');
        
        // Start server (ports will be assigned automatically if not specified)
        await server.start();
        
        logger.debug(`Server ${name} started successfully`);
        
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        this.updateServerStatus(name, 'error', errorMsg);
        logger.errorMessage(`Failed to start server ${name}: ${errorMsg}`);
        throw error;
      }
    });

    await Promise.all(startPromises);
  }

  private updateServerStatus(
    serverName: string, 
    status: ServerInfo['status'], 
    error?: string, 
    startTime?: Date
  ): void {
    const info = this.serverInfo.get(serverName);
    if (info) {
      info.status = status;
      if (error) info.error = error;
      if (startTime) info.startTime = startTime;
      if (status === 'stopped') {
        delete info.error;
        delete info.startTime;
      }
    }
  }

  private startHealthMonitoring(): void {
    // Health check every 30 seconds
    this.healthCheckInterval = setInterval(async () => {
      await this.performHealthChecks();
    }, 30000);

    logger.debug('Health monitoring started');
  }

  private async performHealthChecks(): Promise<void> {
    if (this.isShuttingDown) {
      return;
    }

    const healthPromises = Array.from(this.servers.entries()).map(async ([name, server]) => {
      try {
        if (server.status === 'running') {
          // Simple ping test
          const response = await server.handleMessage({
            jsonrpc: '2.0',
            method: 'ping',
            id: `health-check-${Date.now()}`
          });

          if (response.error) {
            throw new Error(response.error.message);
          }

          // Update last successful health check
          const info = this.serverInfo.get(name);
          if (info && info.status === 'error') {
            // Server recovered
            this.updateServerStatus(name, 'running');
            logger.info(`Server ${name} recovered from error state`);
          }
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Health check failed';
        this.updateServerStatus(name, 'error', errorMsg);
        logger.warn(`Health check failed for server ${name}: ${errorMsg}`);
        this.emit('serverHealthCheckFailed', { name, error: errorMsg });
      }
    });

    await Promise.allSettled(healthPromises);
  }

  // Public methods for server management
  async restartServer(serverName: string): Promise<void> {
    const server = this.servers.get(serverName);
    if (!server) {
      throw new Error(`Server ${serverName} not found`);
    }

    logger.info(`Restarting server ${serverName}...`);
    
    try {
      this.updateServerStatus(serverName, 'stopping');
      await server.stop();
      
      this.updateServerStatus(serverName, 'starting');
      await server.start();
      
      logger.success(`Server ${serverName} restarted successfully`);
      
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      this.updateServerStatus(serverName, 'error', errorMsg);
      throw new Error(`Failed to restart server ${serverName}: ${errorMsg}`);
    }
  }

  getServer(serverName: string): MCPServer | undefined {
    return this.servers.get(serverName);
  }

  getServerInfo(serverName: string): ServerInfo | undefined {
    return this.serverInfo.get(serverName);
  }

  getAllServers(): Array<{ name: string; server: MCPServer; info: ServerInfo }> {
    return Array.from(this.servers.entries()).map(([name, server]) => ({
      name,
      server,
      info: this.serverInfo.get(name)!
    }));
  }

  getHealthyServers(): Array<{ name: string; server: MCPServer }> {
    return Array.from(this.servers.entries()).filter(([name]) => {
      const info = this.serverInfo.get(name);
      return info && info.status === 'running';
    }).map(([name, server]) => ({ name, server }));
  }

  async executeToolOnServer(serverName: string, toolName: string, params: any): Promise<ToolResult> {
    const server = this.servers.get(serverName);
    if (!server) {
      return {
        success: false,
        error: `Server ${serverName} not found`
      };
    }

    const info = this.serverInfo.get(serverName);
    if (!info || info.status !== 'running') {
      return {
        success: false,
        error: `Server ${serverName} is not running (status: ${info?.status || 'unknown'})`
      };
    }

    try {
      logger.debug(`Executing tool ${toolName} on server ${serverName}`);
      const result = await server.handleToolCall(toolName, params);
      
      logger.debug(`Tool execution completed: ${toolName} on ${serverName} (success: ${result.success})`);
      return result;

    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      logger.errorMessage(`Tool execution failed: ${toolName} on ${serverName}: ${errorMsg}`);
      
      return {
        success: false,
        error: `Tool execution failed: ${errorMsg}`
      };
    }
  }

  // Server statistics and monitoring
  getManagerStats(): {
    totalServers: number;
    runningServers: number;
    errorServers: number;
    uptime: number;
    totalTools: number;
    totalCapabilities: number;
  } {
    const servers = Array.from(this.serverInfo.values());
    
    return {
      totalServers: servers.length,
      runningServers: servers.filter(s => s.status === 'running').length,
      errorServers: servers.filter(s => s.status === 'error').length,
      uptime: process.uptime(),
      totalTools: servers.reduce((sum, s) => sum + s.tools, 0),
      totalCapabilities: servers.reduce((sum, s) => sum + s.capabilities, 0)
    };
  }

  getServerCapabilities(): Array<{ server: string; domain: string; description: string; keywords: string[] }> {
    const capabilities: Array<{ server: string; domain: string; description: string; keywords: string[] }> = [];
    
    for (const [name, server] of this.servers) {
      for (const capability of server.capabilities) {
        capabilities.push({
          server: name,
          domain: capability.domain,
          description: capability.description,
          keywords: capability.keywords
        });
      }
    }
    
    return capabilities;
  }

  // Configuration management
  async updateServerConfig(serverName: string, config: Partial<ServerConfig>): Promise<void> {
    const existingConfig = this.serverConfigs.get(serverName);
    if (!existingConfig) {
      throw new Error(`Server config for ${serverName} not found`);
    }

    // Update configuration
    const updatedConfig = { ...existingConfig, ...config };
    this.serverConfigs.set(serverName, updatedConfig);

    // If server is running, restart to apply new config
    const info = this.serverInfo.get(serverName);
    if (info && info.status === 'running') {
      await this.restartServer(serverName);
    }

    logger.info(`Configuration updated for server ${serverName}`);
  }

  // Graceful shutdown handling
  async gracefulShutdown(signal: string): Promise<void> {
    logger.info(`Received ${signal}, initiating graceful shutdown...`);
    
    try {
      // Give servers time to finish current operations
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      await this.stop();
      logger.info('Graceful shutdown completed');
      
    } catch (error) {
      logger.errorMessage(`Error during graceful shutdown: ${error instanceof Error ? error.message : 'Unknown error'}`);
      throw error;
    }
  }

  // Method to register custom servers
  registerServer(name: string, server: MCPServer, config: ServerConfig): void {
    if (this.servers.has(name)) {
      throw new Error(`Server ${name} already registered`);
    }

    this.servers.set(name, server);
    this.serverConfigs.set(name, config);
    this.serverInfo.set(name, {
      name,
      status: 'stopped',
      tools: server.toolCount,
      capabilities: server.capabilities.length
    });

    // Set up event listeners for the new server
    this.setupServerEventListeners();

    logger.info(`Custom server ${name} registered successfully`);
  }

  // Method to unregister servers
  async unregisterServer(name: string): Promise<void> {
    const server = this.servers.get(name);
    if (!server) {
      throw new Error(`Server ${name} not found`);
    }

    // Stop server if running
    if (server.status === 'running') {
      await server.stop();
    }

    // Remove from collections
    this.servers.delete(name);
    this.serverConfigs.delete(name);
    this.serverInfo.delete(name);

    logger.info(`Server ${name} unregistered successfully`);
  }
}