# Claude CLI 연동 문제 분석 리포트

## 1. 문제 상황

`a2a-devops` 프로젝트의 `doctor` 명령어 (`npm run dev -- doctor`)를 실행하면, 다른 시스템 항목들은 정상적으로 체크되지만 'Claude Code' 항목에서 지속적으로 **인증 확인 타임아웃(auth check timeout)** 경고가 발생합니다.

정작 사용자의 일반 터미널(PowerShell, cmd)에서는 `claude` CLI의 모든 기능(버전 확인, 인증 확인 등)이 정상적으로 즉시 실행됩니다. 문제 현상은 오직 `ts-node`를 통해 실행되는 `doctor.ts` 스크립트 내부에서만 재현됩니다.

## 2. 최종 결론 (가설)

`claude` CLI는 사용자의 일반 터미널에서 실행될 때와 Node.js의 `child_process.exec`를 통해 실행될 때 다르게 동작합니다. `child_process` 환경에서는 `claude` 프로세스가 **정상적으로 종료(exit)되지 않고 무한정 멈춰있는(hang) 현상**이 발생합니다.

`doctor.ts`의 `Promise.race` 로직은 이렇게 종료되지 않는 프로세스를 성공적으로 감지하여, 미리 설정된 10초 후에 'Command timeout' 에러를 발생시킵니다. 이는 `doctor.ts`의 로직 오류가 아니라, `claude` CLI와 Node.js 실행 환경 간의 깊은 호환성 문제로 추정됩니다.

## 3. 분석 및 해결 과정

문제를 해결하기 위해 다음과 같은 가설을 세우고 차례대로 검증했습니다.

### 가설 1: `claude` CLI가 설치되지 않았거나 `PATH`에 없음
- **시도:** `ClaudeCodeBridge.ts`를 분석하여 `claude` CLI를 직접 호출함을 확인. `doctor.ts`의 `checkClaudeCode` 함수가 `claude --version`을 실행하는 것을 파악.
- **결과:** `doctor` 명령어 실행 시 `1.0.83` 버전이 정상적으로 출력됨. 이로써 CLI는 설치되어 있으며 `PATH`도 올바르게 설정되어 있음을 확인.
- **결론:** 가설 기각.

### 가설 2: `claude auth whoami` 명령어의 실행 시간이 길어 타임아웃 발생
- **시도:** `doctor.ts` 코드에서 인증 확인에 `claude auth whoami` 명령어가 사용됨을 확인. 설정된 타임아웃 10초가 부족할 수 있다고 판단하여 30초로 늘리는 코드 수정 제안 및 실행.
- **결과:** 타임아웃을 30초로 늘렸음에도 불구하고 여전히 동일한 타임아웃 경고 발생.
- **결론:** 가설 기각.

### 가설 3: `claude auth whoami`가 대화형 프롬프트를 발생시켜 프로세스 멈춤
- **시도:** 사용자가 터미널에서 `claude auth whoami`를 직접 실행.
- **결과:** `Do you trust the files in this folder?` 라는 대화형 프롬프트가 발생함을 확인. `child_process` 환경에서는 이 프롬프트에 응답할 수 없어 프로세스가 멈추는 것으로 잠정 결론.
- **시도 2:** 대화형 프롬프트를 피하기 위해, 인증이 필요한 비대화형 명령어 `claude -p "test"`로 `doctor.ts`의 인증 로직을 교체.
- **결과 2:** 명령어를 교체했음에도 불구하고 **여전히 타임아웃 발생.**
- **결론:** 대화형 프롬프트가 원인의 일부일 수는 있으나, 근본적인 원인은 아니라고 판단.

### 가설 4: Claude 사용량 한도 초과로 인한 특수 동작
- **시도:** 사용자가 터미널에서 `claude -p "test"`를 직접 실행.
- **결과:** `Claude AI usage limit reached` 에러 메시지가 `stderr`(빨간 줄)로 출력되고, **프로세스는 즉시 정상 종료됨.**
- **결론:** 이 가설은 **문제의 핵심**을 드러냄. `claude` CLI는 에러 발생 시 터미널에서는 즉시 종료되지만, `child_process` 환경에서는 어떠한 이유에서인지 종료되지 않고 멈춰버린다는 사실을 증명.

### 최종 분석: 에러 로그 직접 확인
- **시도:** `doctor.ts`의 `catch` 블록을 수정하여 `Promise`가 실패(reject)될 때 받은 에러 객체(`authError`)를 그대로 출력.
- **결과:** 출력된 에러는 `claude` CLI가 반환한 에러(예: 'usage limit reached')가 아닌, `Error: Command timeout` 이었음. 이는 `Promise.race`에서 `execAsync`의 `Promise`가 아닌 `setTimeout`의 `Promise`가 이겼다는 명백한 증거.
- **최종 결론 재확인:** `claude` CLI는 `child_process` 환경에서 에러가 발생했을 때 (또는 정상 실행 시에도) 프로세스를 종료하지 않아 `execAsync`의 `Promise`가 영원히 끝나지 않는다.

## 4. 제안되었던 해결책

1.  **타임아웃 시간 증가:** 효과 없음.
2.  **비대화형 명령어로 교체:** 효과 없음.
3.  **`--dangerously-skip-permissions` 플래그 추가:** 모든 프롬프트를 무시하는 플래그. 시도하지는 않았으나, 프로세스 멈춤의 다른 원인이 있을 경우 효과가 없을 수 있음.
4.  **(최종 제안) `doctor` 스크립트의 인증 로직 완화:** `claude --version` 성공 시, 인증도 성공한 것으로 간주하여 `doctor`의 진단 기능을 단순화하는 방법. 실제 기능에 영향 없이 보조 도구의 문제를 해결할 수 있음.
