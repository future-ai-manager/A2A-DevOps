# PRD - A2A DevOps CLI Platform

## Executive Summary
A2A (Agent-to-Agent) DevOps CLI는 자연어를 통해 DevOps 운영을 제어할 수 있는 Node.js 기반 커맨드라인 도구입니다. Claude Code를 활용한 지능형 쿼리 라우팅과 Falco, Prometheus를 위한 전문 MCP 서버를 통해 보안 모니터링 및 메트릭 분석 기능을 제공합니다.

---

## System Architecture

### Core Components
1. **CLI Interface**: Commander.js 기반의 TypeScript CLI 도구
2. **Agent Router**: Claude Code 기반 자연어 쿼리 라우팅 엔진
3. **MCP Servers**: Falco와 Prometheus를 위한 전문 MCP 서버
4. **Web API Server**: Express 기반 REST API 및 웹 UI 서버

### Technology Stack
- **Runtime**: Node.js 18+ with TypeScript
- **CLI Framework**: Commander.js
- **Protocol**: Model Context Protocol (MCP)
- **AI Integration**: Claude Code CLI (로컬 설치 필요)
- **Security Monitoring**: Falco
- **Metrics Monitoring**: Prometheus

---

## Implemented Features

### 1. CLI Commands

#### Core Commands
- `a2a query <query>`: 자연어 쿼리 처리 및 에이전트 라우팅
- `a2a monitor`: 실시간 보안 및 성능 모니터링
- `a2a serve`: 웹 API/UI 서버 시작
- `a2a doctor`: 시스템 의존성 및 설정 검사
- `a2a validate`: 보안 체크리스트 검증

#### Configuration Commands
- `a2a config init`: 설정 초기화
- `a2a config get/set/list/reset`: 설정 관리

#### Specialized Commands
- `a2a security audit/threats/score`: 보안 관련 작업
- `a2a metrics query/alerts/health`: 메트릭 관련 작업
- `a2a status/agents/version`: 시스템 상태 확인

### 2. Falco Security Agent

#### Capabilities
- **Domain**: Security, Compliance, Incident Response
- **Priority**: Critical runtime security monitoring

#### Implemented Tools
1. **detect-threats**: 실시간 보안 위협 탐지
2. **check-rules**: Falco 규칙 검증 및 관리
3. **security-score**: 보안 점수 계산
4. **security-test-validation**: 보안 테스트 검증

#### Features
- 실시간 Falco 이벤트 스트림 연결
- Kubernetes API 통합
- 이벤트 필터링 (룰별, 우선순위별)
- 최대 1000개 이벤트 캐싱

#### Security Categories
- **File System**: /etc, /usr 쓰기 감지, 민감한 파일 접근
- **Process**: 컨테이너 내 프로세스 생성, 쉘 실행 감지
- **Network**: 외부 연결, 의심스러운 트래픽 분석
- **Privilege**: 권한 상승, SetUID/SetGID 실행
- **Container**: 컨테이너 드리프트, 탈출 시도
- **Kubernetes**: API 접근, RBAC 위반, 서비스 어카운트 남용

### 3. Prometheus Monitoring Agent

#### Capabilities
- **Domain**: Metrics, Alerting, Monitoring
- **Priority**: System performance and health monitoring

#### Implemented Tools
1. **query-metrics**: PromQL 쿼리 실행 및 메트릭 조회
2. **get-alerts**: 활성 알럿 조회 및 관리

#### Features
- Prometheus API 연동 (http://localhost:9090)
- Alertmanager 연동 (http://localhost:9093)
- 시스템 헬스 체크 (CPU, 메모리, 디스크)
- 메트릭 요약 정보 제공

### 4. Agent Router

#### Intelligence Features
- 자연어 쿼리 분석
- 도메인 키워드 기반 에이전트 선택
- 우선순위 기반 라우팅
- 컨텍스트 유지

#### Routing Logic
```typescript
// 에이전트 선택 기준
- Security keywords → Falco Agent
- Metrics keywords → Prometheus Agent
- Force routing via --agent parameter
- Default fallback to general agent
```

### 5. Web Server

#### API Endpoints
- Health checks for all agents
- Tool execution endpoints
- Real-time event streaming
- Configuration management

#### Configuration
- Express.js 기반
- Socket.io for real-time updates
- CORS 지원
- SSL/TLS 옵션

---

## Technical Implementation Details

### File Structure
```
src/
├── cli/
│   ├── index.ts                 # Main CLI entry point
│   ├── commands/                # All CLI commands
│   └── utils/                   # Logger, config utilities
├── core/
│   ├── AgentRouter.ts           # Intelligence routing
│   ├── ClaudeCodeBridge.ts      # Claude Code integration
│   ├── FalcoClient.ts           # Falco API client
│   ├── KubernetesClient.ts      # K8s API client
│   └── MCPServerManager.ts      # MCP server management
├── mcp-servers/
│   ├── base/                    # Base MCP server classes
│   ├── falco/                   # Falco MCP server
│   └── prometheus/              # Prometheus MCP server
└── web/                         # Web server components
```

### Dependencies
```json
{
  "dependencies": {
    "commander": "^11.0.0",
    "axios": "^1.6.0",
    "ws": "^8.14.0",
    "express": "^4.18.0",
    "socket.io": "^4.7.0",
    "winston": "^3.11.0",
    "yaml": "^2.3.4"
  }
}
```

### MCP Protocol Integration
- MCP 서버 기본 클래스 (`MCPServer`)
- 도구 기본 클래스 (`Tool`)
- 이벤트 기반 통신
- WebSocket 및 Unix 소켓 지원

---

## Configuration

### Environment Variables
- `A2A_DEBUG`: 디버그 모드 활성화
- `A2A_DRY_RUN`: 시뮬레이션 모드
- `A2A_CONFIG_PATH`: 설정 파일 경로

### Configuration File (config/default.json)
```json
{
  "claude": {
    "path": "claude-code",
    "timeout": 30000
  },
  "servers": {
    "falco": {
      "enabled": true,
      "port": 8001
    },
    "prometheus": {
      "enabled": true,
      "port": 8002,
      "prometheusUrl": "http://localhost:9090"
    }
  },
  "web": {
    "port": 3000,
    "host": "localhost"
  }
}
```

---

## Validation and Testing

### Security Validation Framework
- **Categories**: filesystem, process, network, privilege, container, kubernetes
- **Modes**: safe, aggressive, simulation
- **Test Execution**: 병렬 실행 지원
- **Reporting**: HTML, JSON 형식 리포트 생성

### Integration Points
- Falco 연결 상태 검증
- Prometheus 메트릭 가용성 확인
- Kubernetes 권한 검증
- Claude Code 설치 확인

---

## Operational Requirements

### System Requirements
- Node.js 18+
- Falco (선택적, 보안 기능용)
- Prometheus (선택적, 메트릭 기능용)
- Kubernetes 클러스터 (선택적)
- Claude Code CLI 설치

### Performance Characteristics
- CLI 응답 시간: 2-5초 (쿼리 복잡도에 따라)
- 실시간 이벤트 처리: 최대 1000개 이벤트 캐싱
- 동시 세션: 제한 없음 (리소스 허용 범위 내)

### Fallback Behavior
- Falco 미설치 시: 경고 메시지와 함께 제한된 기능 제공
- Prometheus 미설치 시: 메트릭 기능 비활성화
- 네트워크 오류 시: 로컬 캐시 데이터 활용

---

## Security Considerations

### Authentication
- Claude Code의 기존 인증 활용
- 로컬 설정 파일 보안
- API 키 안전 저장

### Data Protection
- 민감한 로그 데이터 필터링
- 설정 파일 권한 관리
- 메모리 내 민감 정보 자동 정리

### Network Security
- TLS/SSL 지원
- 로컬 서비스와의 안전한 통신
- CORS 정책 적용

---

## Error Handling and Logging

### Logging Framework
- Winston 기반 구조화된 로깅
- 로그 레벨: error, warn, info, debug
- 파일 및 콘솔 출력 지원

### Error Recovery
- 연결 실패 시 자동 재시도
- Graceful degradation
- 상세한 오류 메시지 제공

---

## Future Extensibility

### Agent Extension Points
- 새로운 MCP 서버 추가
- 도구 플러그인 시스템
- 커스텀 라우팅 로직

### Integration Opportunities
- Trivy 취약점 스캐닝
- Grafana 대시보드 연동
- GitOps 도구 통합

---

## Success Metrics

### Technical Metrics
- CLI 명령 성공률: 95% 이상
- 에이전트 가용성: 99% 이상
- 평균 응답 시간: 5초 미만

### Usage Metrics
- 보안 이벤트 탐지 정확도
- 메트릭 쿼리 효율성
- 사용자 생산성 향상

---

## Known Limitations

### Current Scope
- Falco와 Prometheus로 제한된 에이전트
- 기본적인 웹 UI (상세한 대시보드 없음)
- 로컬 설치만 지원 (클라우드 배포 없음)

### Dependencies
- Claude Code CLI 필수 설치
- 외부 서비스에 대한 의존성
- Kubernetes 선택적 의존성

---

This PRD accurately reflects the current implementation of the A2A DevOps CLI platform, focusing on the actually implemented features while providing clear technical specifications for each component.
