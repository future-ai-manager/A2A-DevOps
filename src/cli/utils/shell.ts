import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * 크로스 플랫폼 호환 shell 명령어 실행 유틸리티
 */
export class ShellUtils {
  /**
   * kubectl 명령어를 크로스 플랫폼 호환 방식으로 실행
   * stderr를 적절히 처리하여 Windows/Unix 모두에서 동작
   */
  static async execKubectl(command: string): Promise<{ stdout: string; stderr?: string }> {
    const suppressStderr = process.platform === 'win32' ? '2>nul' : '2>/dev/null';
    const fullCommand = `${command} ${suppressStderr}`;
    
    try {
      const result = await execAsync(fullCommand);
      return { stdout: result.stdout };
    } catch (error) {
      // stderr가 suppress되어도 명령어 실패는 여전히 catch됨
      throw error;
    }
  }

  /**
   * kubectl 명령어를 타임아웃과 함께 실행
   */
  static async execKubectlWithTimeout(
    command: string, 
    timeoutSeconds: number = 10
  ): Promise<{ stdout: string; stderr?: string }> {
    const suppressStderr = process.platform === 'win32' ? '2>nul' : '2>/dev/null';
    const fullCommand = `${command} --request-timeout=${timeoutSeconds}s ${suppressStderr}`;
    
    return await execAsync(fullCommand);
  }

  /**
   * 일반 명령어를 크로스 플랫폼 호환 방식으로 실행
   */
  static async execSuppressStderr(command: string): Promise<{ stdout: string; stderr?: string }> {
    const suppressStderr = process.platform === 'win32' ? '2>nul' : '2>/dev/null';
    const fullCommand = `${command} ${suppressStderr}`;
    
    return await execAsync(fullCommand);
  }

  /**
   * stderr redirection을 크로스 플랫폼 방식으로 생성
   */
  static getStderrRedirection(): string {
    return process.platform === 'win32' ? '2>nul' : '2>/dev/null';
  }

  /**
   * null device 경로를 크로스 플랫폼 방식으로 반환
   */
  static getNullDevice(): string {
    return process.platform === 'win32' ? 'nul' : '/dev/null';
  }
}