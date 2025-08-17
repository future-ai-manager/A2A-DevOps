import winston from 'winston';
import path from 'path';
import { existsSync, mkdirSync } from 'fs';
import chalk from 'chalk';

export type LogLevel = 'error' | 'warn' | 'info' | 'verbose' | 'debug';

export class Logger {
  private static instance: Logger;
  private logger: winston.Logger;
  private currentLevel: LogLevel = 'info';

  private constructor() {
    // Ensure log directory exists
    const logDir = process.env.A2A_LOG_DIR || path.join(process.env.HOME || process.cwd(), '.a2a', 'logs');
    if (!existsSync(logDir)) {
      mkdirSync(logDir, { recursive: true });
    }

    // Configure Winston logger
    this.logger = winston.createLogger({
      level: process.env.A2A_LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
      ),
      defaultMeta: { service: 'a2a-cli' },
      transports: [
        // File transport for all logs
        new winston.transports.File({
          filename: path.join(logDir, 'error.log'),
          level: 'error',
          maxsize: 5242880, // 5MB
          maxFiles: 5
        }),
        new winston.transports.File({
          filename: path.join(logDir, 'combined.log'),
          maxsize: 5242880, // 5MB
          maxFiles: 5
        })
      ]
    });

    // Add console transport in development or debug mode
    if (process.env.NODE_ENV !== 'production' || process.env.A2A_DEBUG === 'true') {
      this.logger.add(new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.timestamp({ format: 'HH:mm:ss' }),
          winston.format.printf(({ level, message, timestamp, ...meta }) => {
            let logMessage = `${timestamp} ${level}: ${message}`;
            if (Object.keys(meta).length > 0) {
              logMessage += ` ${JSON.stringify(meta)}`;
            }
            return logMessage;
          })
        )
      }));
    } else {
      // Add minimal console transport for production
      this.logger.add(new winston.transports.Console({
        level: 'warn',
        format: winston.format.combine(
          winston.format.simple(),
          winston.format.printf(({ level, message }) => {
            switch (level) {
              case 'error':
                return chalk.red(`❌ ${message}`);
              case 'warn':
                return chalk.yellow(`⚠️ ${message}`);
              case 'info':
                return chalk.blue(`ℹ️ ${message}`);
              default:
                return message;
            }
          })
        )
      }));
    }
  }

  public static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  public setLevel(level: LogLevel): void {
    this.currentLevel = level;
    this.logger.level = level;
  }

  public getLevel(): LogLevel {
    return this.currentLevel;
  }

  public error(message: string, meta?: any): void {
    this.logger.error(message, meta);
  }

  public warn(message: string, meta?: any): void {
    this.logger.warn(message, meta);
  }

  public info(message: string, meta?: any): void {
    this.logger.info(message, meta);
  }

  public verbose(message: string, meta?: any): void {
    this.logger.verbose(message, meta);
  }

  public debug(message: string, meta?: any): void {
    this.logger.debug(message, meta);
  }

  // Convenience methods with colored output for CLI
  public success(message: string): void {
    console.log(chalk.green(`✅ ${message}`));
    this.info(message);
  }

  public warning(message: string): void {
    console.log(chalk.yellow(`⚠️ ${message}`));
    this.warn(message);
  }

  public errorMessage(message: string): void {
    console.log(chalk.red(`❌ ${message}`));
    this.error(message);
  }

  public highlight(message: string): void {
    console.log(chalk.cyan(`💡 ${message}`));
    this.info(message);
  }

  public step(message: string): void {
    console.log(chalk.blue(`🔄 ${message}`));
    this.info(message);
  }

  // Method to create child logger with additional metadata
  public child(meta: any): winston.Logger {
    return this.logger.child(meta);
  }

  // Method to log HTTP requests
  public httpRequest(method: string, url: string, statusCode?: number, duration?: number): void {
    const message = `${method} ${url}`;
    const meta = { method, url, statusCode, duration };
    
    if (statusCode && statusCode >= 400) {
      this.error(message, meta);
    } else {
      this.debug(message, meta);
    }
  }

  // Method to log MCP server operations
  public mcpOperation(server: string, operation: string, success: boolean, duration?: number): void {
    const message = `MCP ${server}: ${operation}`;
    const meta = { server, operation, success, duration };
    
    if (success) {
      this.debug(message, meta);
    } else {
      this.error(message, meta);
    }
  }

  // Method to log agent routing decisions
  public agentRouting(query: string, agent: string, confidence: number, reasoning?: string): void {
    const message = `Query routed to ${agent} (confidence: ${confidence.toFixed(2)})`;
    const meta = { query, agent, confidence, reasoning };
    this.info(message, meta);
  }

  // Method to log security events
  public securityEvent(event: any): void {
    const message = `Security event: ${event.rule} (${event.severity})`;
    const meta = { ...event, type: 'security' };
    
    if (event.severity === 'critical' || event.severity === 'high') {
      this.error(message, meta);
    } else {
      this.warn(message, meta);
    }
  }

  // Method to log performance metrics
  public performanceMetric(name: string, value: number, unit?: string, labels?: Record<string, string>): void {
    const message = `Metric ${name}: ${value}${unit || ''}`;
    const meta = { name, value, unit, labels, type: 'metric' };
    this.debug(message, meta);
  }

  // Method to start a timer
  public startTimer(label: string): () => void {
    const start = Date.now();
    return () => {
      const duration = Date.now() - start;
      this.debug(`Timer ${label}: ${duration}ms`, { label, duration, type: 'timer' });
      return duration;
    };
  }

  // Method to log with structured context
  public withContext(context: Record<string, any>): {
    error: (message: string, meta?: any) => void;
    warn: (message: string, meta?: any) => void;
    info: (message: string, meta?: any) => void;
    verbose: (message: string, meta?: any) => void;
    debug: (message: string, meta?: any) => void;
  } {
    const contextLogger = this.logger.child(context);
    return {
      error: (message: string, meta?: any) => contextLogger.error(message, meta),
      warn: (message: string, meta?: any) => contextLogger.warn(message, meta),
      info: (message: string, meta?: any) => contextLogger.info(message, meta),
      verbose: (message: string, meta?: any) => contextLogger.verbose(message, meta),
      debug: (message: string, meta?: any) => contextLogger.debug(message, meta)
    };
  }

  // Method to flush logs (useful for testing)
  public flush(): Promise<void> {
    return new Promise((resolve) => {
      this.logger.on('finish', resolve);
      this.logger.end();
    });
  }

  // Method to get log file paths
  public getLogFiles(): { error: string; combined: string; directory: string } {
    const logDir = process.env.A2A_LOG_DIR || path.join(process.env.HOME || process.cwd(), '.a2a', 'logs');
    return {
      error: path.join(logDir, 'error.log'),
      combined: path.join(logDir, 'combined.log'),
      directory: logDir
    };
  }

  // Method to configure structured logging for different environments
  public configureForEnvironment(env: 'development' | 'production' | 'test'): void {
    switch (env) {
      case 'development':
        this.setLevel('debug');
        break;
      case 'production':
        this.setLevel('info');
        break;
      case 'test':
        this.setLevel('error');
        break;
    }
  }

  // Method to create a request/response logger middleware
  public createMiddleware() {
    return (req: any, res: any, next: any) => {
      const start = Date.now();
      const timer = this.startTimer(`${req.method} ${req.url}`);
      
      res.on('finish', () => {
        const duration = timer();
        this.httpRequest(req.method, req.url, res.statusCode, duration);
      });
      
      next();
    };
  }
}