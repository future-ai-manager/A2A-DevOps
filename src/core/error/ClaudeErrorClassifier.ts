import { ClaudeErrorType } from './types';

export class ClaudeErrorClassifier {
  /**
   * Claude Code 에러 메시지를 분석하여 에러 타입을 분류
   */
  static classifyError(stderr: string, exitCode: number): ClaudeErrorType {
    const errorText = stderr.toLowerCase();
    
    // Claude Code의 실제 에러 패턴들
    const errorPatterns: Record<ClaudeErrorType, RegExp[]> = {
      USAGE_LIMIT: [
        /usage limit/i,
        /rate limit/i,
        /try again/i,
        /quota.*exceeded/i,
        /too many requests/i,
        /wait.*minutes?/i,
        /reset.*\d+:\d+/i
      ],
      
      AUTH_REQUIRED: [
        /authentication/i,
        /login/i,
        /unauthorized/i,
        /not authenticated/i,
        /invalid.*token/i,
        /session.*expired/i,
        /please.*authenticate/i
      ],
      
      QUOTA_EXCEEDED: [
        /billing/i,
        /subscription/i,
        /payment/i,
        /upgrade.*plan/i,
        /account.*suspended/i,
        /credit.*exhausted/i
      ],
      
      NETWORK_ERROR: [
        /network/i,
        /connection/i,
        /timeout/i,
        /unreachable/i,
        /dns/i,
        /socket/i,
        /econnrefused/i,
        /enotfound/i
      ],
      
      INVALID_REQUEST: [
        /invalid/i,
        /malformed/i,
        /bad request/i,
        /syntax error/i,
        /parse error/i,
        /format.*incorrect/i
      ],

      UNKNOWN_ERROR: []
    };

    // 에러 패턴 매칭
    for (const [errorType, patterns] of Object.entries(errorPatterns)) {
      if (errorType === 'UNKNOWN_ERROR') continue;
      
      for (const pattern of patterns) {
        if (pattern.test(errorText)) {
          return errorType as ClaudeErrorType;
        }
      }
    }

    // Exit code로도 판단
    switch (exitCode) {
      case 1:
        return 'INVALID_REQUEST';
      case 2:
        return 'AUTH_REQUIRED';
      case 3:
        return 'NETWORK_ERROR';
      case 4:
        return 'USAGE_LIMIT';
      default:
        return 'UNKNOWN_ERROR';
    }
  }

  /**
   * 에러 메시지에서 재시도 시간 추출
   */
  static extractRetryTime(errorMessage: string): string | undefined {
    // "Try again at 3:00 PM" 패턴
    const timePatterns = [
      /try again at (\d{1,2}:\d{2}\s*[AP]M)/i,
      /available in (\d+\s*minutes?)/i,
      /reset.*(\d{1,2}:\d{2})/i,
      /wait (\d+)\s*minutes?/i
    ];

    for (const pattern of timePatterns) {
      const match = errorMessage.match(pattern);
      if (match) {
        return match[1];
      }
    }

    return undefined;
  }

  /**
   * 에러의 심각도 판단
   */
  static getErrorSeverity(errorType: ClaudeErrorType): 'low' | 'medium' | 'high' | 'critical' {
    switch (errorType) {
      case 'USAGE_LIMIT':
        return 'medium';
      case 'AUTH_REQUIRED':
        return 'high';
      case 'QUOTA_EXCEEDED':
        return 'critical';
      case 'NETWORK_ERROR':
        return 'medium';
      case 'INVALID_REQUEST':
        return 'low';
      default:
        return 'medium';
    }
  }
}