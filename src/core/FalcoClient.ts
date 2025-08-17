import { EventEmitter } from 'events';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';

const execAsync = promisify(exec);

export interface FalcoEvent {
  time: string;
  rule: string;
  priority: string;
  source: string;
  tags: string[];
  output: string;
  output_fields: Record<string, any>;
  hostname: string;
}

export interface FalcoConnection {
  type: 'grpc' | 'http' | 'file' | 'socket';
  endpoint: string;
  port?: number;
  secure?: boolean;
}

/**
 * Falco 실시간 이벤트 클라이언트
 * 다양한 연결 방식 지원: gRPC, HTTP, 로그 파일, Unix 소켓
 */
export class FalcoClient extends EventEmitter {
  private connection: FalcoConnection | null = null;
  private isConnected: boolean = false;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectInterval: NodeJS.Timeout | null = null;
  private eventStream: any = null;

  constructor() {
    super();
    this.setMaxListeners(50); // 많은 리스너 허용
  }

  /**
   * Falco에 연결 시도 (자동 감지)
   */
  async connect(): Promise<boolean> {
    try {
      // 1. gRPC API 연결 시도
      if (await this.tryGrpcConnection()) {
        return true;
      }

      // 2. HTTP API 연결 시도  
      if (await this.tryHttpConnection()) {
        return true;
      }

      // 3. Unix 소켓 연결 시도
      if (await this.trySocketConnection()) {
        return true;
      }

      // 4. 로그 파일 모니터링
      if (await this.tryFileConnection()) {
        return true;
      }

      // 5. systemd journal 모니터링
      if (await this.tryJournalConnection()) {
        return true;
      }

      throw new Error('모든 Falco 연결 방식 실패');
    } catch (error) {
      this.emit('error', error);
      return false;
    }
  }

  /**
   * gRPC API 연결 시도
   */
  private async tryGrpcConnection(): Promise<boolean> {
    try {
      // Falco gRPC 서비스 확인 (기본 포트: 5060)
      const grpcPorts = [5060, 5061, 5062];
      
      for (const port of grpcPorts) {
        try {
          await execAsync(`timeout 3 nc -z localhost ${port}`);
          
          this.connection = {
            type: 'grpc',
            endpoint: 'localhost',
            port: port,
            secure: false
          };

          await this.startGrpcStream();
          this.isConnected = true;
          this.emit('connected', { type: 'grpc', port });
          return true;
        } catch (portError) {
          continue;
        }
      }
      
      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * HTTP API 연결 시도
   */
  private async tryHttpConnection(): Promise<boolean> {
    try {
      const httpPorts = [8765, 8080, 9090];
      
      for (const port of httpPorts) {
        try {
          // Falco HTTP endpoint 확인
          const { stdout } = await execAsync(`timeout 3 curl -s http://localhost:${port}/api/v1/events || echo "failed"`);
          
          if (!stdout.includes('failed')) {
            this.connection = {
              type: 'http',
              endpoint: `http://localhost:${port}`,
              port: port
            };

            await this.startHttpStream();
            this.isConnected = true;
            this.emit('connected', { type: 'http', port });
            return true;
          }
        } catch (portError) {
          continue;
        }
      }
      
      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * Unix 소켓 연결 시도
   */
  private async trySocketConnection(): Promise<boolean> {
    try {
      const socketPaths = [
        '/var/run/falco.sock',
        '/var/run/falco/falco.sock',
        '/tmp/falco.sock'
      ];

      for (const socketPath of socketPaths) {
        try {
          if (fs.existsSync(socketPath)) {
            // 소켓 파일 권한 확인
            const stats = fs.statSync(socketPath);
            if (stats.isSocket()) {
              this.connection = {
                type: 'socket',
                endpoint: socketPath
              };

              await this.startSocketStream();
              this.isConnected = true;
              this.emit('connected', { type: 'socket', path: socketPath });
              return true;
            }
          }
        } catch (socketError) {
          continue;
        }
      }
      
      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * 로그 파일 모니터링 연결
   */
  private async tryFileConnection(): Promise<boolean> {
    try {
      const logPaths = [
        '/var/log/falco.log',
        '/var/log/falco/falco.log',
        '/var/log/syslog' // Falco가 syslog로 출력하는 경우
      ];

      for (const logPath of logPaths) {
        try {
          if (fs.existsSync(logPath)) {
            // 로그 파일 읽기 권한 확인
            await fs.promises.access(logPath, fs.constants.R_OK);
            
            this.connection = {
              type: 'file',
              endpoint: logPath
            };

            await this.startFileStream();
            this.isConnected = true;
            this.emit('connected', { type: 'file', path: logPath });
            return true;
          }
        } catch (fileError) {
          continue;
        }
      }
      
      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * systemd journal 모니터링
   */
  private async tryJournalConnection(): Promise<boolean> {
    try {
      // systemd journal에서 Falco 로그 확인
      const { stdout } = await execAsync('journalctl -u falco -n 1 --no-pager 2>/dev/null || echo "no_journal"');
      
      if (!stdout.includes('no_journal')) {
        this.connection = {
          type: 'socket',
          endpoint: 'journal'
        };

        await this.startJournalStream();
        this.isConnected = true;
        this.emit('connected', { type: 'journal' });
        return true;
      }
      
      return false;
    } catch (error) {
      return false;
    }
  }

  /**
   * gRPC 스트림 시작 (실제 구현은 추후 gRPC 라이브러리 사용)
   */
  private async startGrpcStream(): Promise<void> {
    // TODO: @grpc/grpc-js 라이브러리 사용하여 실제 gRPC 클라이언트 구현
    // 현재는 시뮬레이션
    this.eventStream = setInterval(() => {
      // gRPC 연결에서 실시간 이벤트 수신 시뮬레이션
      this.emit('event', {
        time: new Date().toISOString(),
        rule: 'gRPC Test Event',
        priority: 'INFO',
        source: 'grpc',
        tags: ['test'],
        output: 'gRPC 연결 테스트 이벤트',
        output_fields: {},
        hostname: 'localhost'
      });
    }, 30000); // 30초마다 테스트 이벤트
  }

  /**
   * HTTP 스트림 시작
   */
  private async startHttpStream(): Promise<void> {
    // HTTP 폴링 또는 Server-Sent Events 구현
    this.eventStream = setInterval(async () => {
      try {
        const { stdout } = await execAsync(`curl -s ${this.connection!.endpoint}/api/v1/events || echo "[]"`);
        const events = JSON.parse(stdout);
        
        for (const event of events) {
          this.emit('event', event);
        }
      } catch (error) {
        this.emit('error', `HTTP 폴링 오류: ${error}`);
      }
    }, 5000); // 5초마다 폴링
  }

  /**
   * Unix 소켓 스트림 시작
   */
  private async startSocketStream(): Promise<void> {
    // Unix 소켓에서 실시간 데이터 읽기
    // 현재는 시뮬레이션
    this.eventStream = setInterval(() => {
      this.emit('event', {
        time: new Date().toISOString(),
        rule: 'Socket Test Event',
        priority: 'WARNING',
        source: 'socket',
        tags: ['socket'],
        output: 'Unix 소켓 연결 테스트 이벤트',
        output_fields: {},
        hostname: 'localhost'
      });
    }, 20000); // 20초마다 테스트 이벤트
  }

  /**
   * 파일 스트림 시작 (실시간 tail)
   */
  private async startFileStream(): Promise<void> {
    try {
      // tail -f 명령으로 실시간 로그 모니터링
      const tailProcess = require('child_process').spawn('tail', ['-f', this.connection!.endpoint]);
      
      tailProcess.stdout.on('data', (data: Buffer) => {
        const lines = data.toString().split('\n').filter(line => line.length > 0);
        
        for (const line of lines) {
          const event = this.parseFalcoLogLine(line);
          if (event) {
            this.emit('event', event);
          }
        }
      });

      tailProcess.stderr.on('data', (data: Buffer) => {
        this.emit('error', `파일 스트림 오류: ${data.toString()}`);
      });

      this.eventStream = tailProcess;
    } catch (error) {
      throw new Error(`파일 스트림 시작 실패: ${error}`);
    }
  }

  /**
   * Journal 스트림 시작
   */
  private async startJournalStream(): Promise<void> {
    try {
      // journalctl -f로 실시간 journal 모니터링
      const journalProcess = require('child_process').spawn('journalctl', ['-u', 'falco', '-f', '--no-pager', '-o', 'json']);
      
      journalProcess.stdout.on('data', (data: Buffer) => {
        const lines = data.toString().split('\n').filter(line => line.length > 0);
        
        for (const line of lines) {
          try {
            const journalEntry = JSON.parse(line);
            const event = this.parseJournalEntry(journalEntry);
            if (event) {
              this.emit('event', event);
            }
          } catch (parseError) {
            // JSON 파싱 실패는 무시
          }
        }
      });

      this.eventStream = journalProcess;
    } catch (error) {
      throw new Error(`Journal 스트림 시작 실패: ${error}`);
    }
  }

  /**
   * Falco 로그 라인 파싱
   */
  private parseFalcoLogLine(line: string): FalcoEvent | null {
    try {
      // Falco 로그 형식: 타임스탬프 Priority Rule Output
      const falcoRegex = /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[Z\+\-\d:]*)\s+(\w+)\s+(.*?)\s+(.+)/;
      const match = line.match(falcoRegex);
      
      if (match) {
        const [, time, priority, rule, output] = match;
        
        return {
          time,
          rule,
          priority,
          source: 'file',
          tags: this.extractTags(output),
          output,
          output_fields: this.extractFields(output),
          hostname: require('os').hostname()
        };
      }
      
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Journal 엔트리 파싱
   */
  private parseJournalEntry(entry: any): FalcoEvent | null {
    try {
      if (entry.MESSAGE && entry.MESSAGE.includes('falco')) {
        return {
          time: entry.__REALTIME_TIMESTAMP ? new Date(parseInt(entry.__REALTIME_TIMESTAMP) / 1000).toISOString() : new Date().toISOString(),
          rule: 'Journal Entry',
          priority: entry.PRIORITY || 'INFO',
          source: 'journal',
          tags: ['journal', 'falco'],
          output: entry.MESSAGE,
          output_fields: entry,
          hostname: entry._HOSTNAME || 'localhost'
        };
      }
      
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * 출력에서 태그 추출
   */
  private extractTags(output: string): string[] {
    const tags: string[] = [];
    
    // 일반적인 Falco 태그 패턴 감지
    if (output.includes('container')) tags.push('container');
    if (output.includes('k8s') || output.includes('kubernetes')) tags.push('kubernetes');
    if (output.includes('file') || output.includes('write') || output.includes('read')) tags.push('filesystem');
    if (output.includes('network') || output.includes('connection')) tags.push('network');
    if (output.includes('privilege') || output.includes('sudo') || output.includes('root')) tags.push('privilege');
    
    return tags;
  }

  /**
   * 출력에서 필드 추출
   */
  private extractFields(output: string): Record<string, any> {
    const fields: Record<string, any> = {};
    
    // 키=값 패턴 추출
    const fieldPattern = /(\w+)=([^\s]+)/g;
    let match;
    
    while ((match = fieldPattern.exec(output)) !== null) {
      fields[match[1]] = match[2];
    }
    
    return fields;
  }

  /**
   * 연결 해제
   */
  async disconnect(): Promise<void> {
    if (this.eventStream) {
      if (this.connection?.type === 'file' || this.connection?.type === 'socket') {
        // Process 종료
        this.eventStream.kill();
      } else {
        // Interval 정리
        clearInterval(this.eventStream);
      }
      
      this.eventStream = null;
    }

    if (this.reconnectInterval) {
      clearInterval(this.reconnectInterval);
      this.reconnectInterval = null;
    }

    this.isConnected = false;
    this.connection = null;
    this.emit('disconnected');
  }

  /**
   * 연결 상태 확인
   */
  getConnectionStatus(): { connected: boolean; connection: FalcoConnection | null } {
    return {
      connected: this.isConnected,
      connection: this.connection
    };
  }

  /**
   * 재연결 시도
   */
  private async attemptReconnect(): Promise<void> {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      this.emit('error', new Error('최대 재연결 시도 횟수 초과'));
      return;
    }

    this.reconnectAttempts++;
    this.emit('reconnecting', this.reconnectAttempts);

    const success = await this.connect();
    if (success) {
      this.reconnectAttempts = 0;
      if (this.reconnectInterval) {
        clearInterval(this.reconnectInterval);
        this.reconnectInterval = null;
      }
    } else {
      // 5초 후 재시도
      this.reconnectInterval = setTimeout(() => this.attemptReconnect(), 5000);
    }
  }
}