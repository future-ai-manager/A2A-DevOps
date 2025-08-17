# **아키텍처 - A2A Devops CLI Package**

## 패키지 구조 개요

```
a2a-cli/
├── src/
│ ├── cli/
│ │ ├── index.ts # CLI 진입점
│ │ ├── commands/ # 명령어 구현
│ │ │ ├── query.ts # 자연어 쿼리 핸들러
│ │ │ ├── monitor.ts # 실시간 모니터링 명령어
│ │ │ ├── serve.ts # 웹 UI 서버 명령어
│ │ │ └── doctor.ts # 의존성 검사기
│ │ └── utils/
│ │ ├── logger.ts # 로깅 유틸리티
│ │ └── config.ts # 설정 관리
│ │
│ ├── core/
│ │ ├── ClaudeCodeBridge.ts # Claude Code 연동
│ │ ├── MCPServerManager.ts # MCP 서버 생명주기 관리
│ │ ├── AgentRouter.ts # 에이전트 선택 로직
│ │ └── types.ts # 핵심 타입 정의
│ │
│ ├── mcp-servers/
│ │ ├── base/
│ │ │ ├── MCPServer.ts # 기본 MCP 서버 클래스
│ │ │ └── Tool.ts # 도구 정의 인터페이스
│ │ ├── falco/
│ │ │ ├── FalcoServer.ts # Falco MCP 구현체
│ │ │ ├── tools/ # Falco 특화 도구
│ │ │ │ ├── detect-threats.ts
│ │ │ │ ├── check-rules.ts
│ │ │ │ └── security-score.ts
│ │ │ └── checklist.ts # 보안 체크리스트 정의
│ │ └── prometheus/
│ │ ├── PrometheusServer.ts
│ │ └── tools/
│ │ ├── query-metrics.ts
│ │ └── get-alerts.ts
│ │
│ ├── monitoring/
│ │ ├── EventMonitor.ts # 백그라운드 이벤트 모니터링
│ │ ├── AlertManager.ts # 경고 라우팅 및 알림
│ │ └── integrations/
│ │ ├── slack.ts # Slack 연동
│ │ └── pagerduty.ts # PagerDuty 연동
│ │
│ └── web/
│ ├── server.ts # UI를 위한 Express 서버
│ ├── websocket.ts # WebSocket 핸들러
│ └── api/
│ ├── query.ts # 쿼리 엔드포인트
│ └── status.ts # 시스템 상태 엔드포인트
│
├── tests/
│ ├── unit/
│ │ ├── mcp-servers/
│ │ │ ├── falco.test.ts
│ │ │ └── prometheus.test.ts
│ │ └── core/
│ │ └── ClaudeCodeBridge.test.ts
│ └── integration/
│ ├── cli.test.ts
│ └── e2e.test.ts
│
├── scripts/
│ ├── check-dependencies.js # 설치 후 의존성 검사기
│ ├── setup-mcp.js # MCP 서버 설정 스크립트
│ └── dev-server.js # 개발 서버 실행기
│
├── config/
│ ├── default.json # 기본 설정
│ ├── mcp-servers.json # MCP 서버 레지스트리
│ └── falco-rules.yaml # Falco 규칙 정의
│
├── dist/ # 컴파일된 JavaScript 결과물
├── docs/ # 추가 문서
├── package.json
├── tsconfig.json
├── PRD.md
├── ARCHITECTURE.md
└── QUICK-START.md
```

---
## 핵심 구성요소 (Core Components)

### 1\. CLI 계층 (`src/cli/`)

커맨드 라인 인터페이스 계층은 사용자 상호작용과 명령어 파싱을 처리합니다.

**주요 구성요소:**

  * `index.ts`: 명령어 파싱을 위해 Commander.js를 사용하는 메인 진입점
  * `commands/`: 개별 명령어 구현체
  * `utils/`: 로깅 및 설정을 위한 공용 유틸리티

**명령어 구조:**

```typescript
interface Command {
  name: string; // 이름
  description: string; // 설명
  options: CommandOption[]; // 옵션
  action: (options: any) => Promise<void>; // 실행 함수
}
```

### 2\. 코어 계층 (`src/core/`)

코어 비즈니스 로직 계층으로, AI 연동 및 에이전트 오케스트레이션을 관리합니다.

**ClaudeCodeBridge:**

  * 로컬 Claude Code CLI 실행 관리
  * 프롬프트 구성 및 응답 파싱 처리
  * 재시도 로직 및 에러 핸들링 구현

**MCPServerManager:**

  * MCP 서버의 생명주기 관리
  * 상태 확인(Health checking) 및 자동 재시작
  * 종료 시 리소스 정리

**AgentRouter:**

  * 사용자 쿼리를 분석하여 적절한 에이전트 결정
  * 폴백(fallback) 전략 구현
  * 최적화를 위한 라우팅 기록 유지

### 3\. MCP 서버 (`src/mcp-servers/`)

각 연동 도구를 위한 모델 컨텍스트 프로토콜(MCP) 서버 구현체입니다.

**기본 서버 아키텍처:**

```typescript
abstract class MCPServer {
  abstract name: string; // 이름
  abstract tools: Map<string, Tool>; // 도구 목록

  async start(): Promise<void>; // 시작
  async stop(): Promise<void>; // 중지
  async handleToolCall(name: string, params: any): Promise<any>; // 도구 호출 처리
}
```

**Falco 서버:**

  * Falco CLI 명령어 래핑(wrapping)
  * JSON 출력을 구조화된 데이터로 파싱
  * 보안 체크리스트 상태 유지
  * 반복적인 쿼리를 위한 캐싱 구현

**Prometheus 서버:**

  * Prometheus API를 위한 HTTP 클라이언트
  * PromQL 쿼리 빌더
  * 메트릭 집계 유틸리티
  * 경고 규칙 평가

### 4\. 모니터링 계층 (`src/monitoring/`)

백그라운드 모니터링 및 경고 시스템입니다.

**EventMonitor:**

  * 연속적인 모니터링 모드로 Falco 실행
  * 실시간 이벤트 스트림 파싱
  * 심각도에 기반하여 경고 발생

**AlertManager:**

  * 적절한 채널로 경고 라우팅
  * 경고 중복 제거 구현
  * 알림 전송률 제한(rate limiting) 관리

### 5\. 웹 계층 (`src/web/`)

시각화를 위한 선택적 웹 인터페이스입니다.

**서버 아키텍처:**

  * HTTP API를 위한 Express.js
  * 실시간 업데이트를 위한 Socket.io
  * UI 자산을 위한 정적 파일 제공

**API 엔드포인트:**

  * `POST /api/query`: 자연어 쿼리 처리
  * `GET /api/status`: 시스템 상태 확인
  * `WS /socket`: 실시간 이벤트를 위한 WebSocket


---
## 데이터 흐름 (Data Flow)

### 쿼리 처리 흐름

```
사용자 입력 → CLI 파서 → Claude Code 브릿지 → 에이전트 라우터
    ↓                                            ↓
터미널 출력 ← 응답 포맷터 ← MCP 서버 ← 선택된 에이전트
```

### 이벤트 모니터링 흐름

```
Falco 프로세스 → 이벤트 스트림 → Event Monitor → Alert Manager
                      ↓                ↓
                   상태 저장소         알림(Notifications)
```

---
## 통신 프로토콜 (Communication Protocols)

### MCP 프로토콜

MCP 서버와의 통신은 모델 컨텍스트 프로토콜 명세를 따릅니다:

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

### Claude Code 연동

자식 프로세스(child process) 생성을 통한 Claude Code CLI와의 상호작용:

```typescript
interface ClaudeExecution {
  command: string; // 명령어
  args: string[]; // 인자
  env?: NodeJS.ProcessEnv; // 환경 변수
  timeout?: number; // 타임아웃
}
```

---
## 상태 관리 (State Management)

### 영구 상태 (Persistent State)

  * **Configuration (설정)**: `~/.a2a/config.json` 에 사용자 환경설정 및 API 키 저장
  * **Cache (캐시)**: `~/.a2a/cache/` 에 쿼리 결과 캐싱
  * **Logs (로그)**: `~/.a2a/logs/` 에 작업 로그 저장

### 런타임 상태 (Runtime State)

  * **MCP Server Status**: 서버 상태를 메모리에서 추적
  * **Security Checklist**: 메모리 맵(memory-mapped) 방식의 체크리스트 상태
  * **Alert History**: 최근 경고를 순환 버퍼(circular buffer)에 저장


---
## 에러 처리 전략 (Error Handling Strategy)

### 에러 카테고리

1.  **Recoverable Errors (복구 가능 에러)**: 지수적 백오프를 사용한 재시도
2.  **Configuration Errors (설정 에러)**: 사용자에게 수정을 요청
3.  **Fatal Errors (치명적 에러)**: 상태를 보존하며 정상 종료(Graceful shutdown)

### 에러 응답 포맷

```typescript
interface ErrorResponse {
  code: string; // 코드
  message: string; // 메시지
  details?: any; // 상세 정보
  suggestion?: string; // 제안
  documentation?: string; // 문서 링크
}
```

---
## 보안 고려사항 (Security Considerations)

### 프로세스 격리

  * MCP 서버는 별도의 프로세스에서 실행
  * 파일 시스템 접근에 대한 권한 제한
  * 방화벽 규칙으로 네트워크 접근 제어

### 자격 증명 관리

  * 가능한 경우 시스템 키체인(keychain)에 API 키 저장
  * 환경 변수를 폴백(fallback)으로 사용
  * 민감 데이터를 평문으로 저장하지 않음

### 입력 값 검증

  * CLI 실행 전 모든 사용자 입력 값을 정제(sanitize)
  * PromQL 인젝션(injection) 방지
  * 경로 탐색(Path traversal) 공격 방지


---
## 성능 최적화 (Performance Optimization)

### 캐싱 전략

  * 쿼리 결과는 5분 동안 캐싱
  * 메트릭 데이터는 시간 범위에 따라 캐싱
  * 보안 이벤트는 절대 캐싱하지 않음

### 리소스 관리

  * 최대 3개의 MCP 서버 동시 실행
  * 유휴(idle) 커넥션 자동 정리
  * 메모리 제한 강제 (서버당 500MB)

### 쿼리 최적화

  * 독립적인 작업들의 병렬 실행
  * 오래 실행되는 쿼리의 조기 종료
  * 대용량 데이터셋을 위한 결과 스트리밍


---
## 확장 지점 (Extension Points)

### 새로운 에이전트 추가하기

1.  `src/mcp-servers/` 디렉토리에 새로운 디렉토리 생성
2.  `MCPServer` 추상 클래스 구현
3.  `tools/` 서브디렉토리에 도구 정의
4.  `config/mcp-servers.json` 에 등록
5.  `AgentRouter`에 라우팅 로직 추가

### 커스텀 연동

외부 시스템 연동을 위한 지점:

  * **Notification Channels (알림 채널)**: `NotificationChannel` 인터페이스 구현
  * **Data Sources (데이터 소스)**: `DataSource` 기본 클래스 확장
  * **Visualization (시각화)**: 웹 UI에 컴포넌트 추가


---
## 테스트 전략 (Testing Strategy)

### 단위 테스트 (Unit Tests)

  * 모의(mocked) CLI 출력을 사용한 개별 도구 테스트
  * 핵심 컴포넌트 격리 테스트
  * 에러 시나리오 커버리지

### 통합 테스트 (Integration Tests)

  * End-to-end 명령어 실행
  * 다중 에이전트 협업
  * 성능 벤치마킹

### 테스트 데이터

  * `tests/fixtures/` 에 합성된 Falco 이벤트
  * 샘플 Prometheus 메트릭
  * 모의 Claude Code 응답


---
## 개발 워크플로우 (Development Workflow)

### 로컬 개발

```bash
# 의존성 설치
npm install

# 개발 모드로 실행
npm run dev

# 테스트 실행
npm test

# 프로덕션용으로 빌드
npm run build
```

### 디버그 모드

디버깅을 위한 환경 변수:

  * `DEBUG=a2a:*`: 모든 디버그 출력 활성화
  * `A2A_LOG_LEVEL=trace`: 상세 로깅
  * `A2A_DRY_RUN=true`: 실행 없이 작업 시뮬레이션


---
## 배포 (Deployment)

### NPM 패키지

`@devops/a2a-cli` 로 배포되며 다음을 포함:

  * `dist/` 디렉토리의 컴파일된 JavaScript
  * 타입 정의
  * 설치 후 설정 스크립트

### 도커 이미지

컨테이너를 통한 대안 배포 방식:

```dockerfile
FROM node:18-alpine
RUN npm install -g @devops/a2a-cli
ENTRYPOINT ["a2a"]
```

### 시스템 요구사항

  * Node.js 18.0 이상
  * Claude Code CLI 설치 및 인증 완료
  * Falco 설치 (보안 기능 사용 시)
  * Prometheus 접근 가능 (모니터링 기능 사용 시)
  * 1GB 이상의 가용 RAM
  * 500MB 이상의 디스크 공간