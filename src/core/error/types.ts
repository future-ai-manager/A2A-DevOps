export type ClaudeErrorType = 
  | 'USAGE_LIMIT'
  | 'AUTH_REQUIRED' 
  | 'QUOTA_EXCEEDED'
  | 'NETWORK_ERROR'
  | 'INVALID_REQUEST'
  | 'UNKNOWN_ERROR';

export interface ErrorResponse {
  title: string;
  message: string;
  details?: string;
  actions: string[];
  recoverable: boolean;
  retryAfter?: string;
}

export interface ClaudeErrorDetails {
  originalError: string;
  exitCode: number;
  errorType: ClaudeErrorType;
  recoverable: boolean;
}

export class ClaudeCodeError extends Error {
  public userMessage: ErrorResponse;
  public details: ClaudeErrorDetails;

  constructor(userMessage: ErrorResponse, details: ClaudeErrorDetails) {
    super(userMessage.message);
    this.name = 'ClaudeCodeError';
    this.userMessage = userMessage;
    this.details = details;
  }
}