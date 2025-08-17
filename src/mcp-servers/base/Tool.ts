import { Tool, ToolCall, ToolResult } from '@core/types';

export abstract class BaseTool implements Tool {
  abstract readonly name: string;
  abstract readonly description: string;
  abstract readonly inputSchema: {
    type: "object";
    properties: Record<string, any>;
    required?: string[];
  };

  abstract execute(params: any): Promise<ToolResult>;

  protected validateParams(params: any): boolean {
    const { required = [] } = this.inputSchema;
    
    for (const field of required) {
      if (!(field in params)) {
        return false;
      }
    }
    
    return true;
  }

  protected createSuccessResult(data: any): ToolResult {
    return {
      success: true,
      data
    };
  }

  protected createErrorResult(error: string): ToolResult {
    return {
      success: false,
      error
    };
  }
}