import { EventEmitter } from 'events';
import { MCPMessage, MCPResponse, MCPError, Tool, ToolCall, ToolResult, AgentCapability } from '@core/types';
import { BaseTool } from './Tool';

export abstract class MCPServer extends EventEmitter {
  abstract readonly name: string;
  abstract readonly capabilities: AgentCapability[];
  
  protected tools: Map<string, BaseTool> = new Map();
  protected isRunning = false;
  protected port?: number;
  protected process?: any;

  constructor() {
    super();
    this.initializeTools();
  }

  protected abstract initializeTools(): void;

  async start(port?: number): Promise<void> {
    if (this.isRunning) {
      throw new Error(`MCP Server ${this.name} is already running`);
    }

    this.port = port;
    
    try {
      await this.onStart();
      this.isRunning = true;
      this.emit('started', { server: this.name, port: this.port });
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  async stop(): Promise<void> {
    if (!this.isRunning) {
      return;
    }

    try {
      await this.onStop();
      this.isRunning = false;
      this.emit('stopped', { server: this.name });
    } catch (error) {
      this.emit('error', error);
      throw error;
    }
  }

  async handleMessage(message: MCPMessage): Promise<MCPResponse> {
    try {
      switch (message.method) {
        case 'tools/list':
          return this.listTools(message);
        case 'tools/call':
          return await this.callTool(message);
        case 'ping':
          return this.ping(message);
        default:
          return this.createErrorResponse(
            message.id || 0,
            -32601,
            `Method ${message.method} not found`
          );
      }
    } catch (error) {
      return this.createErrorResponse(
        message.id || 0,
        -32603,
        `Internal error: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  async handleToolCall(name: string, params: any): Promise<ToolResult> {
    const tool = this.tools.get(name);
    if (!tool) {
      return {
        success: false,
        error: `Tool ${name} not found`
      };
    }

    try {
      return await tool.execute(params);
    } catch (error) {
      return {
        success: false,
        error: `Tool execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  protected registerTool(tool: BaseTool): void {
    this.tools.set(tool.name, tool);
  }

  protected listTools(message: MCPMessage): MCPResponse {
    const toolList = Array.from(this.tools.values()).map(tool => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema
    }));

    return {
      jsonrpc: "2.0",
      result: { tools: toolList },
      id: message.id || 0
    };
  }

  protected async callTool(message: MCPMessage): Promise<MCPResponse> {
    const { name, arguments: params } = message.params || {};
    
    if (!name) {
      return this.createErrorResponse(
        message.id || 0,
        -32602,
        'Missing tool name'
      );
    }

    const result = await this.handleToolCall(name, params);
    
    if (result.success) {
      return {
        jsonrpc: "2.0",
        result: result.data,
        id: message.id || 0
      };
    } else {
      return this.createErrorResponse(
        message.id || 0,
        -32603,
        result.error || 'Tool execution failed'
      );
    }
  }

  protected ping(message: MCPMessage): MCPResponse {
    return {
      jsonrpc: "2.0",
      result: { 
        status: "ok", 
        server: this.name,
        timestamp: Date.now()
      },
      id: message.id || 0
    };
  }

  protected createErrorResponse(id: string | number, code: number, message: string, data?: any): MCPResponse {
    return {
      jsonrpc: "2.0",
      error: { code, message, data },
      id
    };
  }

  protected abstract onStart(): Promise<void>;
  protected abstract onStop(): Promise<void>;

  get status(): string {
    return this.isRunning ? 'running' : 'stopped';
  }

  get toolCount(): number {
    return this.tools.size;
  }

  getTools(): Tool[] {
    return Array.from(this.tools.values()).map(tool => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema
    }));
  }
}