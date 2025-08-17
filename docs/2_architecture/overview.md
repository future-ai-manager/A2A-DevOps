# Architecture Documentation - A2A CLI Package

## Package Structure Overview

```
a2a-cli/
├── src/
│   ├── cli/
│   │   ├── index.ts              # CLI entry point
│   │   ├── commands/             # Command implementations
│   │   │   ├── query.ts          # Natural language query handler
│   │   │   ├── monitor.ts        # Real-time monitoring command
│   │   │   ├── serve.ts          # Web UI server command
│   │   │   └── doctor.ts         # Dependency checker
│   │   └── utils/
│   │       ├── logger.ts         # Logging utilities
│   │       └── config.ts         # Configuration management
│   │
│   ├── core/
│   │   ├── ClaudeCodeBridge.ts   # Claude Code integration
│   │   ├── MCPServerManager.ts   # MCP server lifecycle management
│   │   ├── AgentRouter.ts        # Agent selection logic
│   │   └── types.ts              # Core type definitions
│   │
│   ├── mcp-servers/
│   │   ├── base/
│   │   │   ├── MCPServer.ts      # Base MCP server class
│   │   │   └── Tool.ts           # Tool definition interface
│   │   ├── falco/
│   │   │   ├── FalcoServer.ts    # Falco MCP implementation
│   │   │   ├── tools/            # Falco-specific tools
│   │   │   │   ├── detect-threats.ts
│   │   │   │   ├── check-rules.ts
│   │   │   │   └── security-score.ts
│   │   │   └── checklist.ts      # Security checklist definitions
│   │   └── prometheus/
│   │       ├── PrometheusServer.ts
│   │       └── tools/
│   │           ├── query-metrics.ts
│   │           └── get-alerts.ts
│   │
│   ├── monitoring/
│   │   ├── EventMonitor.ts       # Background event monitoring
│   │   ├── AlertManager.ts       # Alert routing and notifications
│   │   └── integrations/
│   │       ├── slack.ts          # Slack integration
│   │       └── pagerduty.ts      # PagerDuty integration
│   │
│   └── web/
│       ├── server.ts              # Express server for UI
│       ├── websocket.ts          # WebSocket handler
│       └── api/
│           ├── query.ts          # Query endpoint
│           └── status.ts         # System status endpoint
│
├── tests/
│   ├── unit/
│   │   ├── mcp-servers/
│   │   │   ├── falco.test.ts
│   │   │   └── prometheus.test.ts
│   │   └── core/
│   │       └── ClaudeCodeBridge.test.ts
│   └── integration/
│       ├── cli.test.ts
│       └── e2e.test.ts
│
├── scripts/
│   ├── check-dependencies.js     # Post-install dependency checker
│   ├── setup-mcp.js              # MCP server setup script
│   └── dev-server.js             # Development server runner
│
├── config/
│   ├── default.json              # Default configuration
│   ├── mcp-servers.json          # MCP server registry
│   └── falco-rules.yaml          # Falco rule definitions
│
├── dist/                         # Compiled JavaScript output
├── docs/                         # Additional documentation
├── package.json
├── tsconfig.json
├── PRD.md
├── ARCHITECTURE.md
└── QUICK-START.md
```

## Core Components

### 1. CLI Layer (`src/cli/`)

The command-line interface layer handles user interactions and command parsing.

**Key Components:**
- `index.ts`: Main entry point using Commander.js for command parsing
- `commands/`: Individual command implementations
- `utils/`: Shared utilities for logging and configuration

**Command Structure:**
```typescript
interface Command {
  name: string;
  description: string;
  options: CommandOption[];
  action: (options: any) => Promise<void>;
}
```

### 2. Core Layer (`src/core/`)

The core business logic layer managing AI integration and agent orchestration.

**ClaudeCodeBridge:**
- Manages local Claude Code CLI execution
- Handles prompt construction and response parsing
- Implements retry logic and error handling

**MCPServerManager:**
- Lifecycle management for MCP servers
- Health checking and automatic restart
- Resource cleanup on shutdown

**AgentRouter:**
- Analyzes user queries to determine appropriate agent
- Implements fallback strategies
- Maintains routing history for optimization

### 3. MCP Servers (`src/mcp-servers/`)

Model Context Protocol server implementations for each integrated tool.

**Base Server Architecture:**
```typescript
abstract class MCPServer {
  abstract name: string;
  abstract tools: Map<string, Tool>;
  
  async start(): Promise<void>;
  async stop(): Promise<void>;
  async handleToolCall(name: string, params: any): Promise<any>;
}
```

**Falco Server:**
- Wraps Falco CLI commands
- Parses JSON output into structured data
- Maintains security checklist state
- Implements caching for repeated queries

**Prometheus Server:**
- HTTP client for Prometheus API
- PromQL query builder
- Metric aggregation utilities
- Alert rule evaluation

### 4. Monitoring Layer (`src/monitoring/`)

Background monitoring and alerting system.

**EventMonitor:**
- Spawns Falco in continuous monitoring mode
- Parses real-time event stream
- Triggers alerts based on severity

**AlertManager:**
- Routes alerts to appropriate channels
- Implements alert deduplication
- Manages notification rate limiting

### 5. Web Layer (`src/web/`)

Optional web interface for visualization.

**Server Architecture:**
- Express.js for HTTP API
- Socket.io for real-time updates
- Static file serving for UI assets

**API Endpoints:**
- `POST /api/query`: Process natural language queries
- `GET /api/status`: System health and status
- `WS /socket`: WebSocket for real-time events

## Data Flow

### Query Processing Flow

```
User Input → CLI Parser → Claude Code Bridge → Agent Router
    ↓                                              ↓
Terminal Output ← Response Formatter ← MCP Server ← Selected Agent
```

### Event Monitoring Flow

```
Falco Process → Event Stream → Event Monitor → Alert Manager
                                      ↓              ↓
                              State Storage    Notifications
```

## Communication Protocols

### MCP Protocol

Communication with MCP servers follows the Model Context Protocol specification:

```typescript
interface MCPMessage {
  jsonrpc: "2.0";
  method: string;
  params?: any;
  id?: string | number;
}

interface MCPResponse {
  jsonrpc: "2.0";
  result?: any;
  error?: MCPError;
  id: string | number;
}
```

### Claude Code Integration

Interaction with Claude Code CLI through child process spawning:

```typescript
interface ClaudeExecution {
  command: string;
  args: string[];
  env?: NodeJS.ProcessEnv;
  timeout?: number;
}
```

## State Management

### Persistent State

- **Configuration**: User preferences and API keys in `~/.a2a/config.json`
- **Cache**: Query results cached in `~/.a2a/cache/`
- **Logs**: Operation logs in `~/.a2a/logs/`

### Runtime State

- **MCP Server Status**: In-memory tracking of server health
- **Security Checklist**: Memory-mapped checklist state
- **Alert History**: Circular buffer of recent alerts

## Error Handling Strategy

### Error Categories

1. **Recoverable Errors**: Retry with exponential backoff
2. **Configuration Errors**: Prompt user for correction
3. **Fatal Errors**: Graceful shutdown with state preservation

### Error Response Format

```typescript
interface ErrorResponse {
  code: string;
  message: string;
  details?: any;
  suggestion?: string;
  documentation?: string;
}
```

## Security Considerations

### Process Isolation

- MCP servers run in separate processes
- Limited permissions for file system access
- Network access controlled by firewall rules

### Credential Management

- API keys stored in system keychain when available
- Environment variable fallback
- No plaintext storage of sensitive data

### Input Validation

- All user inputs sanitized before CLI execution
- PromQL injection prevention
- Path traversal protection

## Performance Optimization

### Caching Strategy

- Query results cached for 5 minutes
- Metric data cached based on time range
- Security events never cached

### Resource Management

- Maximum 3 concurrent MCP servers
- Automatic cleanup of idle connections
- Memory limit enforcement (500MB per server)

### Query Optimization

- Parallel execution of independent operations
- Early termination for long-running queries
- Result streaming for large datasets

## Extension Points

### Adding New Agents

1. Create new directory in `src/mcp-servers/`
2. Implement `MCPServer` abstract class
3. Define tools in `tools/` subdirectory
4. Register in `config/mcp-servers.json`
5. Add routing logic to `AgentRouter`

### Custom Integrations

Integration points for external systems:

- **Notification Channels**: Implement `NotificationChannel` interface
- **Data Sources**: Extend `DataSource` base class
- **Visualization**: Add components to web UI

## Testing Strategy

### Unit Tests

- Individual tool testing with mocked CLI output
- Core component isolation testing
- Error scenario coverage

### Integration Tests

- End-to-end command execution
- Multi-agent coordination
- Performance benchmarking

### Test Data

- Synthetic Falco events in `tests/fixtures/`
- Sample Prometheus metrics
- Mock Claude Code responses

## Development Workflow

### Local Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Run tests
npm test

# Build for production
npm run build
```

### Debug Mode

Environment variables for debugging:

- `DEBUG=a2a:*`: Enable all debug output
- `A2A_LOG_LEVEL=trace`: Detailed logging
- `A2A_DRY_RUN=true`: Simulate operations without execution

## Deployment

### NPM Package

Published as `@devops/a2a-cli` with:
- Compiled JavaScript in `dist/`
- Type definitions
- Post-install setup script

### Docker Image

Alternative deployment as container:
```dockerfile
FROM node:18-alpine
RUN npm install -g @devops/a2a-cli
ENTRYPOINT ["a2a"]
```

### System Requirements

- Node.js 18.0 or higher
- Claude Code CLI installed and authenticated
- Falco installed (for security features)
- Prometheus accessible (for monitoring features)
- 1GB available RAM
- 500MB disk space