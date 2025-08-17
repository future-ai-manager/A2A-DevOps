import { ClaudeErrorType, ErrorResponse } from './types';
import { ClaudeErrorClassifier } from './ClaudeErrorClassifier';

export class ClaudeErrorHandler {
  /**
   * 에러 타입에 따른 사용자 친화적 메시지 생성
   */
  static generateUserMessage(errorType: ClaudeErrorType, originalError: string): ErrorResponse {
    const retryTime = ClaudeErrorClassifier.extractRetryTime(originalError);

    switch (errorType) {
      case 'USAGE_LIMIT':
        return {
          title: '🚫 Claude Code Usage Limit Reached',
          message: 'Your Claude Code usage limit has been reached.',
          details: retryTime ? `You can try again at: ${retryTime}` : 'Check the error message for retry time',
          actions: [
            'Wait for the usage limit to reset',
            'Upgrade your Claude subscription for higher limits',
            'Check your usage dashboard at https://claude.ai',
            'Use smaller queries to reduce token consumption'
          ],
          recoverable: true,
          retryAfter: retryTime
        };

      case 'AUTH_REQUIRED':
        return {
          title: '🔐 Claude Code Authentication Required',
          message: 'Claude Code is not authenticated or your session has expired.',
          details: 'You need to authenticate with your Claude account to use A2A',
          actions: [
            'Run: claude auth login (if available)',
            'Visit https://claude.ai and sign in to your account',
            'Check if you have a valid Claude subscription',
            'Verify your internet connection',
            'Try restarting your terminal and A2A'
          ],
          recoverable: true
        };

      case 'QUOTA_EXCEEDED':
        return {
          title: '💳 Claude Code Subscription Quota Exceeded',
          message: 'Your Claude subscription quota has been exceeded.',
          details: 'You have reached the monthly limit for your current plan',
          actions: [
            'Upgrade your Claude subscription plan',
            'Check billing settings at https://claude.ai/settings/billing',
            'Wait for your quota to reset next billing cycle',
            'Contact Claude support if you believe this is an error'
          ],
          recoverable: false
        };

      case 'NETWORK_ERROR':
        return {
          title: '🌐 Network Connection Error',
          message: 'Unable to connect to Claude servers.',
          details: 'There seems to be a network connectivity issue',
          actions: [
            'Check your internet connection',
            'Verify firewall settings allow Claude Code',
            'Try again in a few moments (server might be temporarily down)',
            'Check Claude status at https://status.anthropic.com',
            'Try using a different network if possible'
          ],
          recoverable: true
        };

      case 'INVALID_REQUEST':
        return {
          title: '❌ Invalid Request Format',
          message: 'The request sent to Claude Code was malformed.',
          details: 'There might be an issue with the query format or A2A configuration',
          actions: [
            'Try a simpler query to test connectivity',
            'Check if special characters in your query are causing issues',
            'Update A2A to the latest version',
            'Report this issue if it persists with simple queries'
          ],
          recoverable: true
        };

      case 'UNKNOWN_ERROR':
      default:
        return {
          title: '⚠️ Unexpected Claude Code Error',
          message: 'An unexpected error occurred while communicating with Claude Code.',
          details: this.truncateErrorMessage(originalError),
          actions: [
            'Try running the command again',
            'Check Claude Code status: claude doctor',
            'Verify Claude Code installation: claude --version',
            'Check your internet connection',
            'If the problem persists, report this error with the details above'
          ],
          recoverable: true
        };
    }
  }

  /**
   * 긴 에러 메시지를 사용자가 읽기 쉽게 잘라냄
   */
  private static truncateErrorMessage(message: string, maxLength: number = 200): string {
    if (message.length <= maxLength) {
      return message;
    }
    
    return message.substring(0, maxLength) + '... (truncated)';
  }

  /**
   * 에러 타입에 따른 아이콘 반환
   */
  static getErrorIcon(errorType: ClaudeErrorType): string {
    switch (errorType) {
      case 'USAGE_LIMIT':
        return '🚫';
      case 'AUTH_REQUIRED':
        return '🔐';
      case 'QUOTA_EXCEEDED':
        return '💳';
      case 'NETWORK_ERROR':
        return '🌐';
      case 'INVALID_REQUEST':
        return '❌';
      default:
        return '⚠️';
    }
  }

  /**
   * 복구 가능 여부에 따른 exit code 반환
   */
  static getExitCode(errorResponse: ErrorResponse): number {
    return errorResponse.recoverable ? 2 : 1;
  }

  /**
   * 에러 심각도에 따른 색상 반환 (chalk color name)
   */
  static getErrorColor(errorType: ClaudeErrorType): string {
    const severity = ClaudeErrorClassifier.getErrorSeverity(errorType);
    
    switch (severity) {
      case 'low':
        return 'yellow';
      case 'medium':
        return 'orange';
      case 'high':
        return 'red';
      case 'critical':
        return 'magenta';
      default:
        return 'red';
    }
  }
}