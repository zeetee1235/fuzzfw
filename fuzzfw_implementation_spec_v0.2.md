# fuzzfw — 임베디드 C/C++ 소스 기반 퍼징 도구 구현 명세서

- **문서 버전:** 0.2 (LLVM IR 분석 및 결정적 하네스 합성 상세화)
- **작성 기준일:** 2026-11-13
- **상태:** 구현 전 기술 명세 / 검증이 필요한 설계 초안
- **제품 유형:** 로컬 및 CI용 CLI, 소스 기반 선택적 호스트 재호스팅(Source-level Selective Host-Lifting)
- **제품명:** `fuzzfw` (작업명; 상표·패키지 중복 별도 검토)

> **v0.2 변경사항:** LLVM 분석 결과·하네스 합성 계획의 구조화된 연결, 입력/문맥 계약 추론, 하네스 생성·검증 게이트, C/C++ 사례, 테스트 및 CI 실패 규약을 보강했다. 원래 v0.1의 제품 범위, 비지원 처리, HAL adapter 승인 원칙은 유지한다.

> 한 문장 정의: 임베디드 C/C++ 프로젝트에서 **실제로 컴파일되는 코드와 실행 의존성**을 분석하고, **검증된 하드웨어 경계만 대체**해 Linux에서 실행 가능한 퍼징 타깃을 구성하며, 발견한 결함을 반복 재현하여 CI에 전달한다.

## 0. 설계 원칙과 가정

### 0.1 반드시 지킬 원칙

1. **원본 동작 보존:** 검사 대상의 처리 로직은 복사·수정하지 않는 것을 원칙으로 한다. 가능한 기존 translation unit(TU: `.c/.cpp`)을 재빌드·재링크한다.
2. **검증되지 않은 자동화 금지:** `NULL` 반환·항상 성공하는 HAL stub을 자동 생성해서 성공으로 처리하지 않는다.
3. **컴파일 성공 ≠ 유효한 퍼징:** 초기화, 실제 대상 함수 도달, 입력 의존 실행, 상태 격리 및 재현을 별도로 검사한다.
4. **결정적 분석:** LLM과 원격 코드 전송을 사용하지 않는다. 컴파일 정보, AST, 타입/심볼 분석, 검증된 규칙 기반이다.
5. **실패는 명시적으로:** 지원 불가 원인, 미해결 심볼, ABI 불일치와 검사 미완료를 오류 코드와 진단으로 노출한다.
6. **CI 우선:** 개발 PC와 CI가 같은 명령 및 결과 형식을 사용한다. 테스트 대상이 0개이거나 필수 타깃을 실행하지 못한 경우 성공으로 보지 않는다.
7. **작은 실행 경로:** 퍼징 루프 안에 Python/별도 RPC/DB를 넣지 않는다. 기존 엔진과 컴파일된 하네스가 실행한다.
8. **서드파티 엔진 교체 가능:** 입력 함수 규약과 결과 수집 규약은 공통으로 유지하되, 엔진 차이는 얇은 adapter로 한정한다.

### 0.2 가정

- 고객사는 적어도 일부 소스코드와 빌드 스크립트를 제공한다. 바이너리 전용 분석은 범위 밖이다.
- 1차 기본 실행 플랫폼은 **Linux x86-64**다. 호스트에서 실행 가능한 소스 또는 명시적인 adapter로 연결 가능한 코드를 먼저 지원한다.
- 고객사 MCU의 기기별 동작을 완벽하게 재현한다는 보장은 제공하지 않는다.
- 최초 제공 대상은 C11/C17 및 **제한된 C++17** 코드를 가진 펌웨어의 통신·파싱·명령 처리 영역이다. C++ 전체 언어 기능·복잡한 객체 그래프 자동 생성은 후속 단계다.
- 코드와 테스트 데이터는 기본적으로 로컬·고객사 runner에만 남는다.

### 0.3 제외할 것

임의 MCU의 완전 에뮬레이션, 커널/RTOS 전용 전체 실행기, 바이너리-only 리호스팅, 임의 DMA/ISR 스케줄 모델, 자동으로 모든 객체 그래프 생성, 모든 C++ 언어 구조 지원, 웹 UI, 중앙 서버, 자체 coverage-guided fuzzing 엔진, LLM 기반 코드 수정, Contiki-NG/Cooja 특정 연동.

---

## 1. 대상 사용자와 사용 시나리오

**주 사용자:** 임베디드 펌웨어 엔지니어와 제품 보안/QA 담당자.

**최소 성공 흐름:** 기존 소스 checkout → 빌드 정보 수집 → 자동 퍼징 가능한 함수 확인 → 필요하면 **한 번만** HAL adapter 지정 → 로컬/CI에서 `fuzzfw check` 실행 → JSON/JUnit/재현 입력 수신.

**대표 시나리오:**

- **S1 단순 파서:** `int decode(const uint8_t *buf, size_t len)`에서 하네스를 자동 생성하고 ASan 크래시를 검출한다.
- **S2 UART 처리:** 원본 `process_packet()` 호출 경로를 유지하며 외부 `HAL_UART_Receive()` 호출만 명시한 adapter로 대체한다.
- **S3 새 펌웨어 버전:** 코드 수정 후 재빌드·기존 corpus 재생·짧은 추가 퍼징을 수행한다. 변경에 따라 깨진 하네스는 이유를 제시하고 CI를 실패시킨다.
- **S4 CI 적용:** 외부 클라우드/대시보드 없이 사내 Linux runner에서 정해진 시간만큼 검사하고 결과를 artifact로 남긴다.

## 2. 버전별 지원 범위

| 범위 | v0.1/P0 | v0.2/P1 | v1.0/P2 |
|---|---|---|---|
| Host OS | Linux x86-64 | 동일 + CI runner 검증 | 추가 배포판 검증 |
| C | C11/C17의 버퍼 인자 함수 | 전역 상태 및 이벤트 진입점 확대 | 실제 펌웨어 다수 |
| C++ | free/static 함수 중 단순 타입 | C++17 생성자·RAII·일부 클래스 | 지원 가능 유형 확대 |
| 빌드 | CMake+Ninja/Make의 compdb; 직접 link 정보/타깃 지정 | CMake File API 연동, Make host build 연결 | 복잡한 임베디드 빌드 profile |
| HAL | 의존성 탐지, 승인된 외부 함수 adapter | 알려진 HAL profile 재사용 | 고급 peripheral contract |
| 입력 | `buffer + length`, 기존 하네스 | UART/네트워크 callback entry | 제한된 이벤트 기반 입력 |
| 엔진 | honggfuzz | libFuzzer adapter/비교 | 필요시 다른 엔진 |
| 실행 | 보수적 독립 실행 기본 | 검증된 persistent mode 선택 | 안정성/성능 최적화 |
| CI | JSON, JUnit, exit code | PR/Nightly corpus 정책 | 버전별 추적/회귀 분석 |

**중요:** `compile_commands.json`은 *개별 컴파일 명령*을 설명하며 최종 링크 입력 및 라이브러리를 완전하게 제공하지 않는다. 링킹을 위해 프로젝트 타깃/빌드 명령/메타데이터를 별도로 받아야 한다.

---

## 3. 시스템 구조

```text
                      C/C++ Project + Build Metadata
                                   │
                                   ▼
  ┌──────────────────────────── fuzzfw CLI ──────────────────────────────┐
  │                                                                    │
  │  Build Importer ──► Clang Analyzer ──► Target Planner              │
  │       │                  │                │                         │
  │       └──────── Build/ABI Metadata ──────┤                         │
  │                                          ▼                         │
  │                             Host Builder / Adapter Binder          │
  │                                          │                         │
  │                                   Harness Generator                │
  │                                          │                         │
  │                               Self-test / Eligibility Gate         │
  │                                          │                         │
  │                                  Engine Adapter                    │
  │                                          │                         │
  │                                  Triage / Reporter                 │
  └──────────────────────────────────────────┼─────────────────────────┘
                                             │
                                  Native fuzz executable
                                             │
                               honggfuzz / sanitizer runtime
```

### 3.1 구현 모듈과 인터페이스

| 모듈 | 언어 | 입력 | 출력 | 책임 |
|---|---|---|---|---|
| `fuzzfw` CLI | Python 3.11+ | CLI, TOML | 작업 지시, 종료 코드 | 검증/분석/빌드/퍼징 orchestration |
| `build_import` | Python | compdb, 빌드 명령, CMake metadata | `build_manifest.json` | 원본 빌드 환경 기록, 분류 |
| `analyze` | C++17/Clang LibTooling | 빌드 manifest, TU | `analysis.json` | AST, 함수, 호출, 타입, 위험 의존성 추출 |
| `ir_analyze` | C++/LLVM New PM | target/host LLVM IR, AST 식별자 | `ir_facts.json` | 메모리·호출·값 흐름 및 하드웨어 의존성 근거 추출(변환 없는 분석 우선) |
| `plan` | Python | analysis, adapters | `plan.json` | 후보 선별·호스트 실행 가능성·진단 |
| `harness` | C++/Python 결정적 코드 생성기 | `harness_plan.json`, 원본 헤더 | 생성 `.c/.cpp` + manifest | 타입·길이·초기화·해제 계약을 보존한 진입점 생성 |
| `host_build` | Python/CMake | TU, 정상화된 컴파일 플래그, adapter | 실행 바이너리, `build_info.json` | 원본 코드 재컴파일/재링크 |
| `runtime` | C11 | 입력, 승인된 adapter | 출력/상태 및 실행 추적 | 입력 주입·최소 clock/IO 추상화 |
| `engine/honggfuzz` | Python wrapper | 바이너리, corpus, 자원 제한 | 엔진 artifact | 외부 엔진 실행만 담당 |
| `triage` | Python | 크래시, 로그, 바이너리 | `finding.json`, repro input | 재현·분류·중복 제거 |
| `report` | Python | 전체 실행 메타데이터 | `summary.json`, `junit.xml` | CI 출력 및 사람이 읽을 결과 |

**제한:** 파이썬은 케이스당 입력을 중재하지 않는다. P0에서는 한 target당 하나의 컴파일된 fuzz binary를 원칙으로 한다.

---

## 4. 상세 기능 요구사항 (FR)

| ID | 요구사항 | 검증 기준 |
|---|---|---|
| FR-01 | 기존 컴파일 데이터베이스를 읽는다 | `arguments`/`command` 형식, 다중 TU 처리 |
| FR-02 | 분석 대상 함수·정확한 소스/타입·컴파일 구성을 식별한다 | 동일 이름의 다른 함수 혼동 없음 |
| FR-03 | 버퍼와 길이의 관계를 타입·사용처에서 식별한다 | 모호할 경우 자동 생성 거부 |
| FR-04 | 전역 변수, 외부 호출, 정적 inline, 비결정성·HAL/MMIO 위험을 기록한다 | 근거 있는 진단 생성 |
| FR-05 | 후보를 Ready-candidate/Adaptable/Blocked로 분류한다 | 검증 전 `Fuzzable` 판정 금지 |
| FR-06 | 원본 TU를 유지해 host 빌드를 구성한다 | 사용한 source/hash/flags 저장 |
| FR-07 | 외부 HAL 함수 경계를 승인된 adapter로 연결한다 | adapter 전·후의 바인딩 기록 |
| FR-08 | 버퍼형 함수용 하네스를 자동 생성한다 | 컴파일 및 정상 corpus 실행 |
| FR-09 | 정상 실행 후 **타깃 함수에 실제 도달**하는지 검사한다 | coverage/호출 증거 남김 |
| FR-10 | 필수 target에서 최소 1회 이상 유효 입력 실행을 확인한다 | 실행 불가이면 CI 오류 |
| FR-11 | sanitizer 크래시·시그널·타임아웃을 별도 분류한다 | raw log/exit 정보 보존 |
| FR-12 | 재현 입력을 동일 환경에서 여러 번 재실행한다 | 재현 성공횟수와 총 횟수 출력 |
| FR-13 | 기존 corpus를 빌드 버전이 바뀌어도 재검증한다 | 새 빌드에서 재실행/유효성 검사 |
| FR-14 | PR 단기 실행과 nightly 장기 실행을 지원한다 | 시간/타깃 예산 제한 |
| FR-15 | 표준 JSON/JUnit/종료 코드로 CI에 연결한다 | GitHub/GitLab 샘플 CI 실증 |
| FR-16 | 빌드·툴체인·adapter·소스 revision을 저장한다 | 같은 artifact로 로컬 재현 가능 |
| FR-17 | 무작위 코드 실행/오탐을 줄이기 위해 허용되지 않은 stub을 차단한다 | 미승인 외부 의존성 Blocked |
| FR-18 | 사용자 소스/로그를 네트워크에 자동 업로드하지 않는다 | 네트워크 연결 없이 기능 동작 |
| FR-19 | AST 선언과 LLVM 함수/디버그 위치를 조인한다 | 불명확한 매핑은 `unknown`, 유사 이름 자동 결합 금지 |
| FR-20 | 포인터/길이/용량/출력 인자 역할을 근거와 함께 판정한다 | 역할별 evidence·confidence·출처 저장 |
| FR-21 | 호출 전제조건과 객체 초기화 출처를 기록한다 | 테스트/호출자/설정 중 어느 것에서 왔는지 명시 |
| FR-22 | 미증명 인자 제약·소유권 관계를 임의 생성하지 않는다 | 모호함이 핵심이면 `adaptable`/`blocked` |
| FR-23 | 정적 분석 결과로 결정적인 `harness_plan`을 작성한다 | 동일 환경 재생성 시 동일 결과 해시 |
| FR-24 | 원본 함수 구현을 그대로 링크하는 하네스를 생성한다 | 함수 본문 임의 복제/수정 없음 |
| FR-25 | C++ 객체 생성·파괴는 관측된 factory/테스트 흐름만 재사용한다 | 유효하지 않은 생성 경로는 자동 생성 금지 |
| FR-26 | 입출력·상태 초기화·리소스 정리를 별도 계약으로 관리한다 | 미검증 persistent 자동 금지 |
| FR-27 | 대상 함수 도달 및 입력 의존 실행을 별도 계측으로 검사한다 | 도달/소비/분기 영향의 증거 수준 분리 |
| FR-28 | 하네스 실패와 타깃 코드 오류를 분리하여 보고한다 | `harness_failure` 자동 제품 결함 확정 금지 |
| FR-29 | 소스 변경 시 생성 계획을 재분석·재검증한다 | 시그니처/ABI/adapter 해시 차이 노출 |
| FR-30 | 도출된 근거, 불확실성 및 미지원 이유를 사람이 확인할 수 있게 출력한다 | `fuzzfw inspect --target`에 evidence 제공 |
| FR-31 | 강제 모의 객체/가짜 NULL context로 하네스를 통과시키지 않는다 | 자체 회귀 fixture에서 무효 문맥 차단 |

### 비기능 요구사항 (NFR)

- **NFR-01 신뢰성:** 미지원 기능·분석 실패·필수 타깃 미실행은 실패 상태로 종료(fail closed).
- **NFR-02 재현성:** 소스 revision, 도구 버전, compiler triple, 실제 flag diff, adapter checksum, 입력 파일을 기록.
- **NFR-03 단순성:** 상주 서비스/데이터베이스 없음. 파일 기반 manifest+artifact.
- **NFR-04 보안:** 임시 빌드와 테스트는 별도 권한 제한된 runner에서 수행. 파일시스템 쓰기 경로와 네트워크를 제한.
- **NFR-05 성능:** 정적 분석·빌드 준비시간과 퍼징 시간 별도 계측; 성능 절대치는 프로젝트별 실험으로 결정.
- **NFR-06 지원의 정직성:** x86-64 host crash가 실제 MCU에서 동일하게 발생함을 보장하지 않음.

---

## 5. 입력·설정·출력 계약

### 5.1 CLI 명령

```bash
# 도구/컴파일러/빌드/엔진 구성 확인
fuzzfw doctor

# 프로젝트 분석 및 후보 출력
fuzzfw scan . --compdb build/compile_commands.json

# 대상별 host-lift 계획 및 차단 사유 조회
fuzzfw plan --target sensor_decode

# 하네스 생성 + 원본 TU host build + self-test
fuzzfw build --target sensor_decode

# 로컬 심층 퍼징
fuzzfw fuzz --time 1h --jobs 8

# 단일 CI 명령: 재분석 → 빌드 → 회귀 검사 → 짧은 퍼징 → 보고
fuzzfw check --time 10m --output fuzzfw-out/

# 재현/보고
fuzzfw replay fuzzfw-out/findings/F0001/input.bin
fuzzfw report --input fuzzfw-out/
```

- `check`는 **self-contained**: 이전에 `scan`을 수동 실행하지 않아도 동작한다(필요한 빌드 메타데이터 및 승인된 설정은 있어야 함).
- CI에서 필수 타깃을 명시하지 않은 경우, **검증된 타깃 목록을 lock/manifest에 명시**하도록 요구한다. 빈 목록이면 기본적으로 설정 오류다.
- `fuzz`는 기존 빌드를 장시간 실행하는 명령이며, `check`는 CI 게이트다.

### 5.2 `fuzzfw.toml` 예시 (제안 스키마)

```toml
schema_version = 1

[project]
source = "."
compdb = "build/compile_commands.json"
source_revision = "auto"

[host]
triple = "x86_64-unknown-linux-gnu"
clang = "clang"
clangxx = "clang++"
# 원래 firmware build와 별개인 host target 제공이 가능할 때 사용
build_command = ["cmake", "--build", "build-host", "--target", "sensor_hostlib"]

[[targets]]
name = "sensor_decode"
symbol = "sensor_decode"
source = "src/sensor.c"
input = "bytes_length"
required = true
max_input_bytes = 4096

# 타깃별 setup/teardown은 자동 추론보다 명시적인 호출을 우선
# setup = "sensor_test_init"
# teardown = "sensor_test_deinit"

[[adapters]]
original_symbol = "HAL_UART_Receive"
replacement_source = "tests/fuzzfw/adapters/uart.c"
contract = "tests/fuzzfw/contracts/uart.json"
# 대체 함수의 타입·효과 범위·호출 환경 검증에 사용

[ci]
mode = "pr"
engine = "honggfuzz"
time_seconds = 600
jobs = 2
fail_on_new_reproduced = true
incomplete_is_failure = true
```

**설정 규칙:**

- 읽기 전용 소스경로와 생성물 경로를 구분한다. 기본 생성물은 `.fuzzfw/`에 저장한다.
- `build_command`는 **셸 문자열이 아닌 argv 배열**로 실행한다(`subprocess.run(args, shell=False)` 방식). 파이프·리다이렉션은 허용하지 않으며 필요한 경우 별도 빌드 스크립트 경로를 명시적으로 등록한다.
- `source_revision="auto"`는 Git HEAD가 있으면 수집하되, 작업트리가 dirty면 dirty 상태와 파일 hash를 추가 기록한다.
- 명시된 adapter는 원본 소스코드가 **해당 함수와 동일한 타입·ABI 계약**을 사용할 때만 허용한다.

### 5.3 결과 및 내부 데이터 파일

```text
.fuzzfw/
├── build_manifest.json         # 원본 컴파일/호스트 환경
├── analysis.json               # 함수와 의존성 분석
├── plan.json                   # 후보와 지원 판정
├── lock.json                   # 타깃/툴체인/adapter 결속
├── generated/                  # 생성 하네스, 빌드 스크립트
└── build/                      # 계측 대상 바이너리

fuzzfw-out/
├── summary.json                # CI 판정·전체 메트릭
├── junit.xml                   # CI 표준 테스트 결과
├── build-info.json             # 소스/컴파일러/링크/adapter fingerprint
├── diagnostics.json            # 지원 안 되는 코드와 오류 원인
├── corpus/<target>/            # 재검증 후 살아 있는 입력
└── findings/<id>/
    ├── input.bin
    ├── finding.json
    ├── sanitizer.log
    ├── replay.sh                # 입력/빌드 해시 확인 포함
    └── repro.json
```

**호환성:** JSON 필드에는 `schema_version` 필수; 새 필드 추가는 허용하되 기존 필드 의미 변경에는 버전 증가 필요.

### 5.4 `analysis.json`의 핵심 필드

```json
{
  "schema_version": 1,
  "functions": [
    {
      "id": "function-id-hash",
      "language": "c",
      "name": "sensor_decode",
      "qualified_name": "sensor_decode",
      "source": "src/sensor.c",
      "signature": "int(const unsigned char*, size_t)",
      "input_model": {"kind": "bytes_length", "buffer_arg": 0, "length_arg": 1},
      "direct_callees": ["crc16", "parse_header"],
      "unresolved_calls": [],
      "global_reads": [],
      "global_writes": [],
      "hardware_flags": [],
      "classification": "ready_candidate",
      "reasons": []
    }
  ]
}
```

`function-id-hash`는 단순 라인 번호가 아닌 Clang USR 등 선언 식별자, **빌드 variant와 링커 심볼 정보**를 조합한다. USR만으로 모든 소스 이동·오버로드·빌드 variant의 의미를 안정적으로 추적할 수 있다고 가정하지 않는다.

---

## 6. Clang Analyzer 상세

### 6.1 입력 데이터 품질 검사

1. `compile_commands.json` 존재 및 JSON 스키마 검증.
2. 입력의 `directory`, `file`, `arguments`/`command`를 정규화한다. Clang 문서상 `arguments` 우선.
3. 원본 compiler triple, include path, `-D`, `-include`, 언어 표준, warning, 최적화 및 의존 플래그 수집.
4. 동일 TU가 서로 다른 제품 profile로 컴파일되면 **서로 다른 variant**로 저장.
5. cross-compiler 전용 입력이 Clang AST로 파싱되지 않으면 원인 기록. *마음대로 매크로를 제거해 성공 처리하지 않는다.*

### 6.2 AST 수집

`ClangTool` + `ASTMatchers`와 필요한 `RecursiveASTVisitor`를 사용하여 아래 노드를 수집한다.

- `FunctionDecl` / `CXXMethodDecl`, `ParmVarDecl`, `RecordDecl`/`CXXRecordDecl`
- `CallExpr`, `CXXConstructExpr`, 간접 호출과 `MemberExpr`
- `DeclRefExpr`, `VarDecl`, `UnaryOperator`(역참조), `ArraySubscriptExpr`
- `AsmStmt`, `AtomicExpr`, `volatile` 대상 역참조, 정수→포인터 캐스팅
- 호출에 전달되는 버퍼·길이·상수·자료 흐름의 제한된 관계

**주의:** 전역 정적 call graph는 가상 함수·함수 포인터·inline ASM·다른 TU의 간접 호출을 완전하게 파악할 수 없다. 분석 결과에는 `unresolved_indirect_calls`, `unknown_effects`가 필수다.

### 6.3 입력 후보 판정

P0에서 자동 생성하는 하네스는 아래 유형으로 제한한다.

- `fn(const uint8_t*, size_t)` / `fn(uint8_t*, size_t)` (가변 여부는 시그니처별 처리)
- `fn(const char*, size_t)` 등 **원본 의미를 추정할 수 있는 타입/길이 조합**
- 기존 libFuzzer-style 하네스 또는 사용자 제공 wrapper

P0 제외:

- 자료구조 포인터를 의미 없이 임의 메모리로 만드는 함수
- 파일 디스크립터, DMA, MMIO, OS/RTOS context를 요구하는 함수
- 무제한 자동 객체 그래프 생성·C++ polymorphic state
- 문자열 길이와 버퍼 크기 관계가 모호한 함수

함수 이름의 `parse`, `decode`, `receive`는 **약한 후보 힌트**일 뿐 Ready 판정 근거로 단독 사용하지 않는다.

### 6.4 후보 우선순위 (설명 가능한 규칙)

`score = + 외부 입력 경계 명확성 + 기존 테스트/seed 존재 + 의미 있는 분기/메모리 처리 - 초기화 미확정 - 간접 호출 불확실성 - 하드웨어 의존성`

수치 가중치는 v0.1에서 실험용 설정이며 **지원 가능 여부 분류와 위험도 점수를 혼동하지 않는다.** 위험 연산이 많더라도 실행 불가능하면 `Blocked`다.

### 6.5 하드웨어 의존성 플래그

- `MMIO_DIRECT`: 상수 주소/레지스터 범위로의 volatile 역참조(탐지는 보수적 추정)
- `ISR_ENTRY`: irq handler 속성/표준 vector/알려진 callback
- `DMA_ASYNC`: DMA 호출/버퍼 소유권이 불확실한 경우
- `ARCH_ASM`: CPU 전용 inline ASM 및 builtin
- `HAL_EXTERNAL`: 정의 미확인 또는 known HAL namespace 호출
- `RTOS_CONTEXT`: 작업·락·스케줄러 의존
- `ABI_LAYOUT`: packed/bitfield/endianness/포인터 크기 차이가 관찰되는 경우
- `INDIRECT_UNKNOWN`: 호출 대상이 불명확한 함수 포인터/virtual dispatch
- `INIT_REQUIRED`: 초기화된 객체/전역 상태 필요

플래그는 ‘취약점’이 아니라 **테스트 실행 가능성을 판단하는 근거**다.

---

## 6A. LLVM IR 분석기 상세 명세 (v0.2 신규)

### 6A.1 역할과 불변식

Clang AST는 선언·원본 타입·호출 위치·C++ 객체 구조를 확인하는 **소스 수준 근거**이며, LLVM IR은 컴파일된 연산에서 **포인터 사용, 메모리 접근, 분기/값 흐름, 간접 호출, 타깃 의존성**을 추가로 관찰하는 근거다. 어느 하나가 다른 하나를 대체하지 않는다. **LLVM IR을 분석한다고 정상적인 초기화 문맥이 자동으로 증명되는 것은 아니다.**

P0의 LLVM 분석기는 **read-only** 모듈/함수 분석을 우선한다. 사용자 코드 변환 pass, 자동 MMIO rewrite, 임의 값 강제 삽입은 구현하지 않는다. LLVM Pass를 개발하더라도 입력 ABI와 실행 의미를 바꾸는 변환은 별도 실험 기능으로 격리해야 한다.

### 6A.2 분석 빌드와 호스트 실행 빌드의 분리

```text
Original build metadata (compiler flags, target triple)
    ├── AST analysis: original compilation context if Clang-compatible
    ├── IR analysis: Clang-supported target IR if feasible
    └── Host build: Linux host triple + explicit and audited build delta
```

- 임베디드 GCC/IAR/Keil 전용 문법을 Clang이 파싱하지 못할 수 있다. 이 경우 원본 compiler 명령을 무조건 Clang으로 치환하지 않고, 진단을 남기며 필요한 profile 수정은 승인받는다.
- 분석 IR과 호스트 IR은 다른 데이터 레이아웃일 수 있다. `target triple`, `datalayout`, 주소 공간, 구조체 정렬, conditional build 차이를 각각 기록한다. **서로 다른 빌드의 IR이 같다고 가정하지 않는다.**
- 우선 `-O0 -g -fno-discard-value-names` 형태의 분석 profile을 제안할 수 있으나, 실제 프로젝트의 전처리기 정의와 타깃 ABI를 바꾸면 결과가 달라질 수 있다. `-O0` IR은 최적화된 production IR과 다르므로 별도 `-O1`/실제 빌드 비교는 이후 단계다.
- TU별 비트코드 분석에서 다른 TU 호출 대상은 `external/unknown`으로 남길 수 있다. 전체 링크 정보가 있는 경우에만 ThinLTO/whole-program 분석의 제한된 추가 근거를 사용할 수 있다.

### 6A.3 LLVM New Pass Manager 기반 분석 파이프라인

```text
clang compile → .bc per translation unit
   │
   ├─ Symbol / source map (DICompileUnit, DISubprogram, DILocation)
   ├─ CallSite summary (direct, indirect, external)
   ├─ Memory operation summary (load/store/memcpy/memmove/atomic)
   ├─ Pointer provenance / alias hints (AA, GEP, phi, bitcast)
   ├─ Conditional data use (icmp / switch / branch dependencies)
   └─ Platform effects (volatile, atomic, addrspace, constant-address cast, asm)
   │
   ▼
ir_facts.json + unresolved facts + provenance
```

구현은 `ModuleAnalysis/FunctionAnalysis` 스타일의 분석 Pass 또는 `opt` 플러그인으로 시작한다. `AAResults`, `MemorySSA`, DominatorTree, LoopInfo 등 기존 LLVM 분석 결과를 **근거로 참조**하되, `MayAlias`를 `MustAlias`로 승격하지 않는다. MemorySSA의 연결도 전역·스레드·디바이스 의미를 완벽하게 증명하지 않는다.

**최소 추출 항목**

| IR 사실 | LLVM에서 볼 지점 | 활용 | 주의 |
|---|---|---|---|
| 포인터 사용 | `load`, `store`, `getelementptr`, `phi`, `select` | 버퍼가 실제 사용되는지 | interprocedural 불완전 |
| 길이 의존 | `icmp`, `branch`, `zext/sext`, `trunc`, 인덱스 계산 | 버퍼/len 역할 보강 | 단순 비교만으로 전체 안전 제약 증명 불가 |
| 메모리 쓰기 | `store`, `memcpy`, `memmove`, 호출 side effect | 입력/출력 인자 구별 | alias 미해결은 unknown |
| 간접 호출 | `call`의 callee·함수 포인터 | 미해결 의존성 진단 | 가상 dispatch 자동 확정 금지 |
| 전역 상태 | `GlobalVariable`, load/store | 초기화/상태 오염 위험 | 동시성/장치 의미 미포함 |
| 주변장치 의존 | `volatile` memory op, inttoptr, inline asm | MMIO/특수 ISA 위험 후보 | 모든 volatile = MMIO는 아님 |
| ABI 경계 | `DataLayout`, addrspace, integer widths, struct GEP | host/target 차이 진단 | source `packed` 등 AST 교차 검증 |

**P0에서 하지 않는 것:** 정밀 interprocedural symbolic execution, 완전한 points-to 분석, 임의 IRQ/DMA 이벤트 시뮬레이션, 자동 구조체 불변식 합성, 전역 memory-safety 증명.

### 6A.4 AST↔IR 심볼 조인

AST에서 `ASTFunctionID`(Clang USR + 원본 qualified signature + build variant)를 만든다. IR에서는 **mangled/linker symbol, 함수 타입, 디버그 메타데이터, CU와 소스파일**을 추출한다. `link_symbol + build_variant + CU`를 우선으로 조인하고, 인라이닝 등으로 모호하면 `mapping_status=ambiguous`를 남긴다. 소스 line number 또는 demangled name 하나만으로 결합하지 않는다.

`-g`가 없는 IR이나 LTO로 합쳐진 함수에서는 AST와 IR의 정확한 소스 매핑이 불가능할 수 있다. 이 경우 해당 fact의 적용 범위를 TU/symbol 단위로 낮추고, 중요한 인자 판단은 AST/호출자 증거를 우선한다.

### 6A.5 분석 결과 계약 예시

```json
{
  "schema_version": 1,
  "function_id": "hash-of-ast-identity-and-variant",
  "target_triple": "arm-none-eabi",
  "host_triple": "x86_64-unknown-linux-gnu",
  "ir_mapping": "resolved",
  "arguments": [
    {"index": 0, "observed_use": ["memory_read", "indexed_by_arg_1"], "may_escape": false},
    {"index": 1, "observed_use": ["compare_with_constant", "loop_bound"]}
  ],
  "global_effects": ["read:g_state"],
  "hardware_flags": [],
  "unknowns": ["external_call:opaque_helper"],
  "evidence": [
    {"kind":"gep_index", "ir_symbol":"sensor_decode", "source":"src/sensor.c:45", "confidence":"observed"}
  ]
}
```

위 JSON은 **미구현 제안 스키마**다. `confidence`는 통계적 정확도 수치가 아니라 `verified/observed/heuristic/unknown` 같은 근거 수준으로 기록한다.

### 6A.6 실패 정책

- IR 생성이 불가능하되 AST와 빌드 정보만으로 충분한 단순 `buffer+length` 함수는 `analysis_mode=AST_ONLY`로 제한적으로 진행 가능하다. 결과에는 이 축소를 표시한다.
- 하드웨어 경계 판단이 IR 근거에 의존하거나 ABI 레이아웃이 핵심이면 IR 분석 실패 시 `E_IR_UNAVAILABLE`로 `adaptable/blocked` 처리한다.
- 정적 분석의 근거 불충분은 '안전함'이나 '유효한 하네스'의 근거가 아니다.

---

## 7. Selective Host-Lifting 계획 알고리즘

### 7.1 원칙

- **최소 절단점 탐색:** 선택된 진입점에서 필요한 원본 함수/TU를 유지한다. 하드웨어나 특정 플랫폼에 닿는 호출은 후보 경계로 표시한다.
- **링크 단위 최적화:** source-to-source 복사보다 원본 TU/object와 명시적 adapter의 재링크를 우선한다.
- **검증된 대체만 허용:** 지원 가능한 HAL 경계의 의미 계약이 없으면 자동 `return 0`으로 통과시키지 않는다.
- **모든 변형은 기록:** host compiler 설정 변경/제외된 모듈/대체한 심볼을 manifest에 저장한다.

### 7.2 알고리즘 의사코드

```text
for candidate in analyzed_functions:
    deps = compute_conservative_dependencies(candidate)
    if unresolved_function_pointer_or_init_graph(deps):
        require_explicit_entry_or_mark_adaptable()
    original_tus = select_required_translation_units(deps)
    hardware_edges = find_mmio_hal_arch_boundaries(deps)
    for edge in hardware_edges:
        adapter = lookup_approved_adapter(edge)
        if not adapter or not adapter.contract_valid:
            mark_blocked_or_adaptable(edge)
    if critical_target_abi_semantics_are_unverified():
        mark_blocked("ABI_NOT_VERIFIED")
    else:
        emit_host_build_plan(original_tus, adapters, harness)
        build_and_selftest_before_marking_ready()
```

**중요:** 호출 그래프는 보수적 근사다. 정적 분석만 통과한 후보는 `Ready-candidate`다. 실제 빌드·스모크 테스트·실행 진전 검증 후에만 `Fuzzable`로 승격한다. `Ready`라는 UI 단축 라벨은 검증된 타깃에만 사용한다.

### 7.3 원본 빌드와 호스트 빌드의 구분

- `original profile`: 임베디드용 compiler triple, MCU 옵션, 링커 스크립트 및 원본 매크로.
- `host profile`: Linux용 Clang/Clang++, sanitizer, 엔진 계측, 링크 타깃.
- `delta report`: 제거한 `-mthumb/-mcpu`, 추가한 include, 전처리기 정의, 선택된 adapter, 호스트 ABI.
- CPU/OS 전용 매크로가 원본 로직을 바꾸는 경우, 자동으로 조용히 제거해서 빌드 성공으로 취급하지 않는다. 차이 이유와 검사 범위를 공개한다.

### 7.4 컴파일·링크 의존성

- **첫 구현:** 기존 호스트 빌드용 라이브러리 타깃(또는 직접 지정한 link objects) 재사용을 기본으로 한다.
- **P1:** CMake File API의 target 정보와 실제 link command 연계를 도입한다.
- GNU `--wrap=symbol`은 **링크 시 unresolved reference**에 유효하므로, 같은 object 내부에서 이미 해소된 `static`/inline 호출의 일반적 대체 수단이 아니다. 이 경우 빌드를 분리하거나 명시적 코드 구성 변경이 필요하며 자동 지원 범위에서 제외한다.
- `weak` 심볼과 C++ mangling/ODR/interposition은 자동으로 안전한 대체라고 가정하지 않는다.
- 필요한 경우 고객이 제공한 host build target을 직접 사용하는 것이 더 정확하며, 이 경로를 **정식 지원**한다.

### 7.5 Adapter contract

각 adapter는 아래 정보를 정의한다.

```json
{
  "schema_version": 1,
  "original_symbol": "HAL_UART_Receive",
  "prototype": "int(void*, uint8_t*, size_t, uint32_t)",
  "model": "input_source",
  "effects": ["write_buffer", "return_status"],
  "max_write": "min(requested_len, available_input)",
  "valid_context": "uart_handle_initialized",
  "nondeterminism": "none",
  "limitations": ["no_real_interrupt_timing", "no_dma"]
}
```

**검증:** 함수 원형 및 calling convention, 접근 버퍼 한계, 반환 코드 및 필수 선행 조건을 검사한다. 시간/IO 모델의 한계는 보고서에 반드시 포함한다. 계약 검증은 **모델의 현실 충실도를 증명하지 않으며** 최소한의 일관성 검사다.

### 7.6 ABI guard

- 원본 target triple과 host triple, `sizeof(void*)`, `sizeof(size_t)`, 정수 폭, 엔디언, `alignof`, 중요한 `sizeof(struct)`을 기록한다.
- `packed` 구조체/비트필드/메모리 맵 레지스터를 원본과 다르게 해석할 위험이 있으면 `ABI_LAYOUT` 진단. 단순히 호스트 포인터 폭이 다르다는 이유만으로 모든 대상이 자동 차단되지는 않는다. **검사할 경로가 타깃 ABI의 레이아웃에 의존하고 이를 보존/검증할 수 없을 때** 차단한다. 그렇지 않은 경우에도 `HOST_ONLY` 한계를 보고한다.
- 호스트 ASan 결과는 **호스트 코드의 결함 재현**이며 실제 MCU 취약점의 자동 입증이 아니다.

---

## 8. 결정적 하네스 합성 알고리즘 (v0.2 전면 상세화)

### 8.1 문제 정의, 성공 조건, 우선순위

**입력:** `build_manifest + analysis.json + ir_facts.json + 사용자가 승인한 adapters + 기존 unit tests/corpus`.

**출력:** 재현 가능한 `harness_plan.json`, 생성 `.c/.cpp` 파일, 빌드 설정, 원본/호스트 변경 내역, 자체 검증 증거, 미지원 진단.

**목표:** 공격자/외부 입력이 들어오는 **현실적인 함수 호출 경계**를 선택하고, 원래 코드와 계약을 존중하면서 **입력값만 변이**시키는 하네스를 자동으로 만든다. 단순한 컴파일 성공, 함수 진입, 커버리지 증가만으로 의미적 유효성을 주장하지 않는다.

하네스 합성은 다음 세 축을 명확히 분리한다.

1. **Entry:** 어느 실제 API/콜백/외부 입력 경계를 호출하는가?
2. **Context:** 정상 실행을 위해 무엇을 먼저 구성하며 어떤 리소스를 해제하는가?
3. **Mutation:** 호출 전제조건을 깨지 않으면서 외부 입력에 해당하는 어떤 값을 변이하는가?

**원칙적 선택 순서:** 기존 퍼징 하네스 재사용 > 실제 호출자/단위 테스트 기반 wrapping > 명확한 `buffer+length` 엔트리 직접 호출 > 명시적 사용자 wrapper. 복잡한 문맥을 추측해 synthesize하는 경로는 P0에서 제외한다.

### 8.2 하네스 알고리즘 전체 흐름

```text
S1. collect_candidates(project, compdb, original_tests)
S2. match_AST_and_IR(candidate) → typed ABI + observed effects
S3. classify_arg_roles(candidate, caller_evidence, IR)
S4. recover_invocation_context(candidate, tests, callers, config)
S5. establish_mutation_contract(buffer, length, capacity, ownership)
S6. select_entry_and_platform_boundary(candidate, adapters)
S7. reject_unknown_critical_constraints()
S8. materialize_harness_plan()  // no code changes yet
S9. generate_source_from_typed_plan() + host_build()
S10. validate(): types → link → seed → reach → sensitivity → stability
S11. label_FUZZABLE_or_emit_exact_reason()
```

P0에서 각 단계를 독립적인 기능 함수와 진단으로 구현한다. `S1~S8`은 부작용 없는 분석·계획, `S9~S11`만 파일 생성/빌드/실행으로 분리한다. 실패한 단계의 이전 결과를 수정하지 않고 다음 결과에 대한 근거를 보존한다.

**계획기 의사코드(규범적):**

```python
for candidate in candidates:
    ast = resolve_exact_declaration(candidate, build_variant)
    ir = lookup_ir_facts(ast, fallback="AST_ONLY")
    roles = infer_roles(ast, ir, existing_callers, tests)
    entry = choose_realistic_entry(candidate, tests, caller_graph)
    context = recover_setup_teardown(entry, tests, callsites, config)
    boundary = resolve_hal_and_abi_dependencies(entry, adapters)
    mutation = derive_mutation_contract(roles, context, boundary)

    reasons = validate_static_contract(ast, ir, context, boundary, mutation)
    if reasons.has_blocking_issue:
        emit_blocked_or_adaptable(candidate, reasons)
        continue

    plan = canonicalize_plan(ast, entry, context, boundary, mutation)
    code = emit_typed_source(plan)
    if not build(code, plan):
        emit_failure("E_HARNESS_BUILD", diagnostics)
        continue
    results = run_eligibility_checks(plan)
    emit_status("fuzzable" if results.required_pass else "not_fuzzable", results)
```

이 알고리즘은 **LLVM IR을 이용해 잘못된 가정을 제거**하는 접근이지, 소스 분석만으로 모든 호출 문맥이 존재한다고 증명한다는 주장이 아니다.

### 8.3 Entry 후보 탐색과 선택

후보 입력 경계는 아래 카테고리로 수집한다.

| Entry 종류 | 우선순위 | P0 지원 | 증거 |
|---|---:|---|---|
| 기존 `LLVMFuzzerTestOneInput`/등록 하네스 | 가장 높음 | 재사용 | 기존 build/target |
| 정상 단위 테스트에서 사용한 공개 API | 높음 | 명시적 setup 재사용에 한해 | unit-test callsite |
| `fn(const uint8_t*, size_t)` 등 독립 함수 | 높음 | 자동 생성 | AST 타입 + 길이 관계 |
| UART / Network 수신 callback | 중간 | 승인 adapter가 있을 때만 | ISR/callback registration |
| 파일/스트림 읽기 루틴 | 중간 | 기존 파일 입력 하네스 우선 | 파일 API 호출 |
| C++ 객체 메서드, 다중 인자 API | 낮음 | 기본 제외 | 생성자/수명·alias 관계 필요 |
| `static` TU-내부 함수 | 별도 판정 | 직접 외부 wrapper 불가 | internal linkage |

같은 함수라도 API 진입점이 여러 개면 **서로 다른 계획**을 생성할 수 있다. 예: `parser_decode()` 직접 경로와 `gateway_on_packet()` 상위 호출 경로를 구별한다. 전자는 빠른 탐색, 후자는 제품 도달 가능성 검증에 활용된다.

중요한 C/C++ 예외: `static` 내부 함수는 별도 TU에서 외부 심볼로 링크할 수 없다. P0는 원본 공개 호출자를 우선한다. 별도 TU에 소스를 `#include`해 재컴파일하거나 동일 소스에 자동 패치를 주입하는 작업은 기본 경로에서 금지한다. 내부 함수 직접 퍼징은 추후 **승인된 build-overlay** 등 별도 기능으로 연구한다.

### 8.4 인자 역할 추론(Role Inference)

P0에서 추론할 최소 역할은 아래와 같다.

- `FUZZ_BYTES`: 외부 입력 바이트가 전달되는 `const uint8_t*`, `const char*`, 제한된 `void*`.
- `FUZZ_BYTES_MUTABLE`: 입력 buffer가 수정될 수 있으므로 복사해서 전달해야 하는 포인터.
- `LOGICAL_LENGTH`: 실제 유효 바이트 수. `size_t`, `uint16_t` 등 **정확한 서명 타입**을 유지.
- `CAPACITY`: 실제 할당 영역의 크기. `len`과 다른 의미일 수 있음.
- `OUTPUT_BUFFER`: 함수가 결과를 기록하는 공간으로, 입력 데이터를 임의 주입하지 않음.
- `CONTEXT`: 생성·초기화 계약을 요구하는 객체/상태 포인터.
- `CONFIG`: 외부 입력과 별도인, 명시적 설정/테스트에서 가져올 값.
- `UNKNOWN`: 근거가 부족한 인자.

각 인자는 독립적인 역할 추론 **근거 배열**을 갖는다. 역할을 단순한 인자 이름으로 확정하지 않는다. 아래 순서로 근거를 수집한다.

1. **타입/const:** `const uint8_t* + size_t`와 같이 가능한 데이터-길이 형태를 후보로 등록.
2. **사용처/IR:** 해당 포인터로 실제 read/write, 길이로 index/bounds/루프 비교가 수행되는지 관찰.
3. **호출자:** `recv(..., buf, cap)` 이후 `parse(buf, received)`처럼 호출과 반환값의 자료흐름이 연결되는지 관찰.
4. **테스트:** 사용자가 만든 버퍼 생성/할당/초기화/호출에서 관계를 찾음.
5. **설정:** 정적 추론으로 불충분한 경우 사용자 확인의 계약을 적용.

증거 충돌 시 `UNKNOWN`/`AMBIGUOUS`, 핵심 인자이면 `adaptable` 처리. **`len`이라는 이름만 보고 배열 길이를 일치시킨 것으로 판정하지 않는다.**

### 8.5 Buffer–Length–Capacity 관계 추론

지원하는 제약 유형(문법화):

```text
len == input_bytes.length
0 <= len <= capacity
capacity == allocation_size(output_buffer)
len <= MAX_PACKET_SIZE
len fits actual integer width (no narrowing/truncation)
ptr lifetime >= target invocation
```

**중요:** `len`은 논리 길이이고 `capacity`는 할당 공간의 최대 길이다. 예를 들어 `parse(buf, len, capacity)`에는 길이와 용량을 같은 값으로 둘 수 있는 상황도 있지만, 그것이 모든 실제 호출을 대표하지는 않는다. P0에서는 실제 호출자/테스트에서 일치 관계가 관찰된 경우 또는 명시적 계약이 있는 경우만 하나의 버퍼 길이에서 함께 유도한다.

```c
int parse(const uint8_t *p, uint16_t n);
```

이 경우 `size > UINT16_MAX`는 **입력을 건너뛰거나 엔진 최대 크기를 줄이는 방식**으로 처리한다. `n = (uint16_t)size`로 조용히 잘라 넣지 않는다. 필요한 경우 `size <= configured_max`도 별도 검사한다.

```c
int process(uint8_t *buf, size_t len);
```

`buf`가 쓰기 가능한 경우 하네스는 입력 데이터를 별도의 writable 버퍼에 복사한다. `len=0`일 때에도 pointer nullability를 멋대로 바꾸지 않는다. 버퍼가 비어 있을 때의 NULL/비NULL 처리는 원본 호출자 또는 명시적 계약에 따른다.

```c
int decode(const uint8_t *p, size_t len, size_t capacity);
```

`len`과 `capacity`의 관계가 관찰되지 않았다면 두 값을 동일하게 고정해 '완전 자동'이라고 주장하지 않는다. 확인된 wrapper·callsite·사용자 계약을 요구한다.

### 8.6 실제 호출 문맥 및 객체 수명 복원

문맥 복원은 아래 신뢰 순서로 수행한다.

1. **ExistingHarness:** 이미 존재하는 하네스의 setup/reset/teardown과 실제 입력 경계 재사용.
2. **UnitTestSequence:** 개발자가 작성한 테스트의 초기화·할당·API 호출 순서에서 관련 코드만 재사용. 상호 의존 인자들은 공통 root definition에서 변이.
3. **CallerSlice:** 실제 제품 호출자의 제한된 backward slice를 분석해 함수 인자의 유래 및 선행 초기화 조건을 제안(자동 추출 불충분이면 검토 요청).
4. **ApprovedFactory/Adapter:** 프로젝트 설정에 등록된 생성·종료 API, HAL contract를 이용.
5. **Direct:** 전역 및 문맥 의존성 없이 독립 호출이 확인된 함수.

특히 `ctx = calloc(1,sizeof(*ctx))`로 생짜 메모리를 만들고 구조체 필드에 가짜 포인터를 넣는 방식은 기본 금지한다. 초기화 함수가 단순한 전역 변수를 세팅한다고 해서 언제나 임의 객체를 생성하는 일반적 규칙이 되지는 않는다.

**문맥 계획의 필수 필드**:

```text
setup_calls[]         // 원본의 실제 초기화 경로 또는 승인된 factory
live_resources[]      // allocator, owner, context and lifetimes
entry_call            // 정확한 호출될 심볼/서명
mutation_bindings[]   // 바이트 입력으로 치환할 근본 정의
teardown_calls[]      // 실제 해제/종료; 실패 경로 포함
reset_policy          // process-isolated or verified reset
provenance[]          // unit test / real caller / adapter / explicit config
unknowns[]            // 입증되지 않은 선행조건·alias·side effects
```

**자원 소유권:** 소유권과 생성/파괴 순서가 알려지지 않았으면 자동 `free()`나 자동 `delete`를 삽입하지 않는다. C++ 클래스는 등록된 factory 및 가시적 소멸자/RAII가 있고 필요한 context가 검증된 경우만 P1에서 지원한다. 생성자 시그니처만 보고 유효한 비기본 생성 인자를 추측하지 않는다.

### 8.7 변이 지점 선정: Root Definition 우선

다수의 인자가 같은 근원 값에서 파생되었다면 서로 따로 변이하지 않는다. 이것은 UTopia의 root-definition 접근에서 취할 수 있는 핵심 교훈이다.

예:

```c
size_t n = packet_size;
uint8_t *p = malloc(n);
memcpy(p, packet_data, n);
parse(p, n);
```

이 경우 `malloc(n)`의 크기, `memcpy()` 길이, `parse()` 길이를 독립적으로 임의 변이하면 *원래 호출자와 다르게* 될 수 있다. 원래 정상 호출 문맥을 유지하는 목표라면 `packet_data/packet_size`의 근원(또는 재현 가능한 동등 표현)에서 변이하고 할당 길이·전달 길이를 같이 유도한다.

단, **원래 외부 인터페이스에서 유효하지 않은 크기·길이가 실제로 전달될 수 있는지**가 검사 목적이라면 원래 호출자가 수행하는 길이 검사를 우회하지 않는지 확인한다. 근본값 연결은 유효성 보존을 위한 규칙이지 발견 가능한 버그 조건을 임의로 제거하는 규칙이 아니다.

### 8.8 HAL / ISR / RTOS 및 비동기 입력에 대한 생성 제약

하드웨어 경계 변이는 '타깃 함수 인자'가 아닌 **입력 제공 이벤트**에서 일어날 수 있다.

예시(승인 계약이 있을 때만): `uart_receive(adapter_context, dst, requested, timeout)`가 `dst`에 최대 `requested` 바이트를 복사하고 실제 반환 상태/길이를 제공. 타깃의 상위 `on_uart_event()` 호출은 그대로 유지한다.

- **HAL stub:** 단순 성공 반환은 금지. 함수 원형, 버퍼 쓰기 길이, 완료/오류 반환, timeouts, 사용 가능한 호출 문맥을 계약화.
- **ISR:** 등록된 실제 callback entry 또는 승인된 synthetic event 경로가 있는 경우만. 무작위 시점 IRQ 호출은 P0 제외.
- **DMA:** 비동기 완료 여부, 버퍼 소유권, transfer length 의미를 검증하지 못하면 `E_DMA_UNMODELED`.
- **RTOS:** 스케줄러/동기화 객체를 자동 가짜 생성하지 않는다. 사용자 제공 host port 또는 검증된 adapter 필요.
- **직접 MMIO/inline ASM:** 자동 값을 넣어 하네스를 강행하지 않는다. P0에서 Blocked.

**중요:** HAL 경계에 fuzz bytes를 공급하는 경우에도 데이터가 목적 버퍼에 들어간 사실, 반환 길이·상태 조건, 그 후 실제 처리 함수가 실행됐는지를 각각 검증한다.

### 8.9 `harness_plan.json` 정규 스키마(핵심 부분)

```json
{
  "schema_version": 2,
  "target": {
    "function_id": "stable-id-with-build-variant",
    "language": "c",
    "entry_kind": "direct_buffer_api",
    "link_symbol": "sensor_decode",
    "source_header": "include/sensor.h",
    "build_variant": "host-debug"
  },
  "role_bindings": [
    {"argument": 0, "role": "FUZZ_BYTES", "source": "fuzz_input", "evidence": ["pointer_read", "callsite"]},
    {"argument": 1, "role": "LOGICAL_LENGTH", "source": "fuzz_input.size", "evidence": ["index_bound"]}
  ],
  "constraints": [
    {"expr": "size <= 4096", "basis": "configured_engine_limit"},
    {"expr": "size <= SIZE_MAX", "basis": "type_width"}
  ],
  "context": {"setup": [], "teardown": [], "reset_policy": "isolated"},
  "platform": {"adapters": [], "abi_guards": ["pointer_width_reviewed"]},
  "analysis": {"ast": "resolved", "ir": "observed", "unknowns": []},
  "validations": ["compile", "link", "seed", "target_reach", "input_use", "stability"],
  "provenance": ["ast", "llvm_ir", "project_build"]
}
```

- JSON은 생성기의 **입출력 계약**이다. 입력 순서·key 정렬·경로 정규화·해시 계산을 고정해 재현성을 확보한다.
- `constraints[].basis`에는 `original_caller`, `unit_test`, `verified_adapter`, `user_contract`, `compiler_abi`, `configured_engine_limit` 등 출처를 명시한다. 휴리스틱은 `heuristic`으로 표시한다.
- 필요한 핵심 제약이 heuristic-only이면 자동 `Fuzzable`로 승격하지 않는다.
- plan에 포함된 adapter를 교체할 때는 계획 및 바이너리 fingerprint를 갱신한다.

### 8.10 P0 자동 생성 C 하네스 예시(입력 크기와 길이 보존)

원본 헤더:

```c
// include/sensor.h
#include <stddef.h>
#include <stdint.h>
int sensor_decode(const uint8_t *packet, size_t packet_len);
```

하네스 생성 결과:

```c
// GENERATED: fuzzfw; do not edit
#include <stddef.h>
#include <stdint.h>
#include "sensor.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 4096) return 0;      // explicit configured max, not inferred parser rule
    (void)sensor_decode(data, size); // original implementation, linked as-is
    return 0;
}
```

- 원본 **헤더를 include**하며 임의 prototype 재선언을 피한다.
- `sensor_decode`의 함수 본문이나 검증 로직은 수정하지 않는다.
- sanitizer와 엔진용 coverage는 `host_build`에서 넣는다. 생성기는 에러를 억제하거나 signal을 삼키지 않는다.
- 생명주기가 없는 단순 함수라도 `input(data,size)`에 의미 있는 데이터가 실제 전달되는지는 동적 검증에서 확인한다.

**mutable buffer 예시:**

```c
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "sensor.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 4096) return 0;
    uint8_t *copy = malloc(size ? size : 1);
    if (!copy) return 0;          // OOM is a harness/resource issue, not target finding
    if (size) memcpy(copy, data, size);
    (void)sensor_decode_mut(copy, size);
    free(copy);
    return 0;
}
```

**제약:** 이 코드는 소유권이 호출자에게 남고, 타깃이 버퍼를 보관하지 않으며, 함수 종료 시 내부 비동기 사용이 없다는 것이 증명되거나 명시된 경우에만 생성한다. `malloc` 실패 시 입력 건너뜀은 하네스 환경 한계로 계측하며, 의도적으로 실패를 숨겨서는 안 된다.

### 8.11 복잡한 호출 문맥/ C++ 하네스 생성 예시 (P1)

원본 API:

```cpp
// product_parser.hpp (example)
class Parser {
public:
    static Parser create_default();  // only when real API exists and verified
    int feed(const unsigned char* data, std::size_t size);
};
```

지원 조건: factory가 실제로 존재하고 안전한 `Parser` 초기 상태를 만들며, 파괴가 RAII로 완료되고, 반복 실행 시 객체가 각 입력에서 새롭게 구성됨을 검증한 경우.

```cpp
#include <cstddef>
#include <cstdint>
#include "product_parser.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 4096) return 0;
    Parser parser = Parser::create_default();
    (void)parser.feed(data, size);
    return 0;
}
```

생성자·factory의 전제조건, 글로벌 등록, 이벤트 루프, throw semantics 등이 불명확하면 C++ 객체를 raw bytes로 `reinterpret_cast`하거나 `memset(0)`으로 꾸며 성공 처리하지 않는다. Exception을 광범위하게 `catch (...)`하여 오류를 숨기는 것도 기본 금지한다.

### 8.12 사용자 작성 wrapper를 공식적인 탈출구로 유지

자동 생성이 `adaptable`로 분류되면 사용자는 **원본 코드를 수정하지 않고** 최소 wrapper 또는 adapter만 제공할 수 있어야 한다.

```c
void fuzzfw_target(const uint8_t *data, size_t size) {
    firmware_test_init();
    app_on_rx(data, size);
    firmware_test_shutdown();
}
```

이 경우에도 종료 시 해제되지 않은 리소스·비동기 작업·전역 상태를 반복 실행해도 되는지는 검증해야 한다. 수동 코드가 있다는 이유로 별도 검증을 건너뛰지 않는다. `manual_adapter_lines` / `manual_harness_lines`를 기업용 지표로 남긴다.

### 8.13 자동 생성 이후 단계별 검증 게이트

| Gate | 방법 | 통과 증거 | 실패 시 |
|---|---|---|---|
| G0 정적 계약 | AST+IR+호출문맥+adapter 확인 | typed plan, 근거·unknown 목록 | `adaptable`/`blocked` |
| G1 컴파일 | 정확한 원본 헤더/host profile | build command, compiler version | `E_HARNESS_BUILD` |
| G2 링크 | 원본 object/TU + 승인 adapter | resolved symbols, link manifest | `E_LINK_GRAPH_UNKNOWN` |
| G3 정상 실행 | seed·empty/boundary 입력 | exit/sanitizer/timeout | `E_HARNESS_SMOKE` |
| G4 타깃 도달 | 함수 진입 계측 또는 caller mapping | entry hit >0 | `E_ENTRY_UNREACHED` |
| G5 입력 연계 | 서로 다른 입력·길이와 경로/값 사용 증거 | `input_consumed` 또는 `weak_sensitivity` | 탐색 효과 경고/심각시 보류 |
| G6 문맥 유효성 | 원본 테스트 호출 순서·factory·adapter 계약 | provenance와 동적 상태 검사 | `E_CONTEXT_INVALID` |
| G7 안정성 | 동일 입력 반복/순서 교차 실행 | repeatability, reset evidence | isolated 전환/`E_STATE_LEAK` |
| G8 크래시 재현 | 동일 입력 독립 재실행 | sanitizer + repro log | `non_reproducing` |

**G5 주의:** 서로 다른 두 입력의 edge coverage가 같다는 이유만으로 입력을 전혀 사용하지 않았다고 단정하지 않는다. 입력 소비 evidence(버퍼 read, API 전달, 반환값 영향 등)와 단순 경로 차이를 구분한다. `input_consumed`는 정확한 메모리 read 관찰 등 계측이 없으면 `unknown`일 수 있다. `unknown`을 `yes`로 기입하지 않는다.

**G6 한계:** 동적 self-test와 제한된 contract 확인도 실제 제품의 모든 도달 가능성을 증명하지 않는다. `HOST_REPRODUCED`와 `DEVICE_CONFIRMED`는 분리된다.

### 8.14 생성 후 provenance와 코드 버전 변경 처리

- `harness_id = hash(function identity, exact build variant, normalized context, mutation contract, adapter contracts)`.
- `source_revision`, ABI data layout, compile options, generated source hash, engine/sanitizer version을 기록한다.
- 소스 내부 변경만 있고 ABI·호출 문맥이 유지되면 같은 **합성 계획을 재검증**한다. 계획 재활용과 테스트 검증 완료를 별개로 취급한다.
- 호출자, 구조체 레이아웃, 타깃 시그니처, adapter 의미 계약이 바뀌면 **plan invalidation + re-analysis**를 수행한다.
- 기존 corpus는 새 바이너리에서 smoke/coverage/reproducer 재검증 후에만 현재 버전용으로 등록한다.

### 8.15 하네스 생성기의 내부 파일 구조 제안

```text
analyzer/
  ast/               # declarations, callsites, types, source mapping
  ir/                # readonly LLVM pass, alias/memory summaries
  join/              # AST↔IR identity/provenance
planner/
  roles.py           # input/len/capacity/context classification
  context.py         # setup/teardown, original caller/test extraction
  boundary.py        # HAL/ABI checks, adapters
  harness_plan.py    # deterministic canonical plan + errors
harness/
  emit_c.py          # C target generator
  emit_cpp.py        # limited C++ target generator
  templates/         # engine-agnostic source templates
  validate.py        # gates G0..G8
runtime/
  adapters/          # only approved hardware models
  replay/            # single-input isolated reproducer driver
```

P0에서는 분석기 하나(`fuzzfw-analyze`), 계획기 하나, C emitter 하나로 시작한다. 파일을 세분화한 것은 책임 경계를 명시하기 위한 설계이고, **서버·플러그인 프레임워크·추상화 계층을 처음부터 크게 만들라는 뜻이 아니다**.

### 8.16 시간/코드 예산 제한과 fallback 정책

| 난이도 | 자동 처리 | 합성 실패 시 |
|---|---|---|
| 단순 `buffer+size_t` 독립 함수 | P0 완전 자동 목표 | 함수/타입/링크 근거 출력 |
| `uint8_t* + uint16_t length` | P0, 길이 overflow guard | 길이 역할 모호하면 `adaptable` |
| 별도 output buffer | P1, 할당/용량 명확할 때 | 사용자 계약 요구 |
| 기존 테스트의 복합 호출 | P1, root-definition 명확할 때 | 수동 wrapper 권고 |
| 복잡한 C++ 객체/가상 함수 | P2 제한 지원 | 검증된 factory/config 요구 |
| 직접 MMIO/ISR/DMA/RTOS 스케줄러 | P0 미지원 | `blocked` 및 구체 의존성 출력 |

**중단 조건:** 정적 문맥 분석에서 미해결 호출/분기 폭발로 분석 예산을 소진하면 `analysis_incomplete`; 호출 그래프 제한 초과 시 자동으로 무한 확장하지 않는다. 사용자가 공개 입력 API/빌드 타깃을 명시해 좁힐 수 있어야 한다.

---

## 9. 퍼징 엔진 인터페이스와 실행 모드

### 9.1 공통 entry 규약

컴파일된 하네스는 가능하면 `LLVMFuzzerTestOneInput(const uint8_t*, size_t)`를 사용한다. **엔진에 따라 추가 링크 드라이버·컴파일 wrapper가 필요**하므로 단순히 엔진 실행 파일 이름만 교체하지 않는다.

P0 honggfuzz 빌더는 `hfuzz-clang`/`hfuzz-clang++`와 필요한 driver/library를 사용한다. 정확한 링크 조합은 해당 honggfuzz 버전에 대한 통합 테스트에서 고정한다. 이후 `libFuzzer`는 동일한 하네스에 `-fsanitize=fuzzer` 링크를 제공하는 별도 adapter로 추가한다.

### 9.2 Engine Adapter 계약

```text
Engine.build(plan) -> instrumented_binary + metadata
Engine.run(binary, corpus_dir, budget, workers, sandbox) -> run_manifest
Engine.collect(run_manifest) -> saved_corpus + raw_findings + stats
Engine.replay(binary, input, runtime_options) -> exit/signal/sanitizer_log
```

엔진이 발생시킨 raw coverage 수치를 동일한 의미의 공통 지표로 임의 환산하지 않는다. 공통 메트릭은 **실행 수·타깃 도달 여부·재현 결함 수·검사 시간**으로 제한하고 엔진별 coverage는 출처를 붙여 저장한다.

### 9.3 실행 모드

| 모드 | 조건 | 이점 | 위험/제약 |
|---|---|---|---|
| `isolated` (기본) | 별도 입력 실행 시 초기 상태 확보 | 입력 간 오염 방지에 유리 | 프로세스 오버헤드 |
| `persistent` (선택) | target reset이 검증됨 | 높은 처리량 | 전역 변수·힙·타이머 상태 누적 위험 |

실제 `isolated`가 **매 케이스 완전히 독립된 MCU 상태**를 뜻하지는 않는다. 해당 host process의 코드·데이터 초기 상태를 뜻하며 외부 파일/공유 자원은 별도로 격리한다.

### 9.4 자원 제한

- 전역 시간 제한, target별 시간 제한, 프로세스 메모리 제한, 입력 크기 제한, 각 케이스 timeout.
- 실행 로그 크기 제한과 실패 시 원시 로그 일부 보관.
- `SIGSEGV`, sanitizer diagnostics, timeout, 비정상 종료를 분리 기록.
- ASan의 큰 가상 주소 매핑 때문에 `RLIMIT_AS`만으로 메모리를 통제하지 않는다. cgroup 기반 실메모리 제한을 우선한다.

---

## 10. 결함 분류 및 재현

### 10.1 Finding 파이프라인

`engine artifact → 독립 재현 → sanitizer symbolization → 고유 finding 분류 → 입력 최소화 → 최소화 입력 재재현 → CI 판정`

- 동일 바이너리/동일 adapter/동일 sanitizer 조건에서 기본 **3회 재현**을 목표로 한다(설정 가능).
- 재현 실패와 간헐성은 숨기지 않는다. `non_reproducing` 또는 `flaky`로 기록한다.
- 최소화한 입력이 동일한 오류를 유발하는지 필수 재검증한다.
- `finding_id`는 sanitizer 유형 + 정상화된 top frame들 + 선택한 entry boundary + 빌드 profile을 바탕으로 만든다. 버전별 주소/라인 변경에 따른 병합 오차를 허용하며 절대적인 취약점 ID로 취급하지 않는다.
- `harness_failure`, `adapter_failure`, `target_crash`, `timeout`, `unknown`을 구분한다. 충돌 의심이면 자동으로 제품 결함으로 확정하지 않는다.

### 10.2 재현 판정 레벨

| 레벨 | 의미 |
|---|---|
| `R0_OBSERVED` | 엔진에서 결함 신호 관측 |
| `R1_HOST_REPRODUCED` | 동일한 host harness에서 재현 |
| `R2_ENTRY_REPRODUCED` | 원래의 입력 처리 경계에서도 재현 |
| `R3_DEVICE_CONFIRMED` | 실제 타깃 장치에서 별도 검증(자동 수행 범위 밖) |

P0의 기본 최대 보증은 R1이다. 입력 경계가 원래 호출 경로인 경우 근거를 붙여 R2로 승격 가능하나 무조건 R2로 분류하지 않는다.

### 10.3 `finding.json` 예시

```json
{
  "schema_version": 1,
  "id": "F0001",
  "target": "sensor_decode",
  "kind": "heap-buffer-overflow",
  "origin": "target_crash",
  "reproduction": {"level": "R1_HOST_REPRODUCED", "success": 3, "attempts": 3},
  "source": {"file": "src/sensor.c", "line": 184},
  "build_manifest_sha256": "...",
  "adapter_manifest_sha256": "...",
  "input_sha256": "...",
  "scope_note": "host recompiled code; MCU behavior not yet confirmed"
}
```

---

## 11. CI 설계

### 11.1 `check`의 정확한 의미

`check = 환경 검사 → manifest 검증 → 빌드/하네스 자체 검사 → 필수 corpus 회귀 → 정해진 시간 추가 퍼징 → 결함 재현/분류 → 보고 → 종료코드`

성공 조건은 **정해진 필수 타깃 모두 유효하게 실행되었고, 실패시키기로 한 신규 재현 결함이 없으며, 모든 필수 단계가 완료되었다는 것**이다. 시간 예산 내 필수 타깃을 모두 처리하지 못하면 incomplete다.

### 11.2 종료 코드

| Code | 의미 | CI |
|---|---|---|
| `0` | 정의된 검사가 완료됐고 실패 기준에 해당하는 신규 재현 결함 없음 | Pass |
| `1` | 기준에 해당하는 신규 재현 결함 있음 | Fail |
| `2` | 빌드·환경·자체 검사 실패 또는 필수 검사 미완료 | Fail |
| `3` | 잘못된 사용자 설정·CLI 입력 | Fail |

기존/신규 판단은 **명시적인 baseline** 비교로만 수행한다. baseline이 없는 첫 실행에서는 모든 재현 finding을 신규로 간주하거나 명시적인 `--bootstrap-baseline` 승인이 필요하다. 임의의 실패를 자동 무시하지 않는다.

### 11.3 PR / Nightly / Release 정책

| 유형 | 목표 | 예시 예산(정책값; 성능 보장 아님) |
|---|---|---|
| PR | 기존 corpus 재생 + 영향 대상 단기 퍼징 | 5~15분 |
| Nightly | 전체 등록 타깃·긴 fuzz + corpus 확장 | 1~6시간 |
| Release | 필수 타깃 전체 검사, 누적 finding 회귀, ABI/adapter 검토 | 팀 정책 |

`changed-only` 최적화는 P2. 정적 영향 분석이 불완전한 상태에서 이를 기본으로 두면 미검사 구간이 생길 수 있다. P0는 **명시된 required target 전체** 실행.

### 11.4 GitHub Actions 예시 (설계 인터페이스)

```yaml
name: fuzzfw
on: [pull_request]
permissions:
  contents: read
jobs:
  fuzz:
    runs-on: ubuntu-24.04
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@v4
      - name: Install pinned fuzzfw toolchain
        run: ./ci/install-fuzzfw.sh
      - name: Generate compilation database
        run: cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
      - name: Run bounded fuzz check
        run: fuzzfw check --time 600 --output fuzzfw-out
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: fuzzfw-results
          path: fuzzfw-out/
```

- 위는 제품 인터페이스가 구현된 이후의 **설계 예시**이며 `install-fuzzfw.sh`는 배포 시 제공할 설치 절차를 나타내는 자리표시자다.
- 타깃 코드 실행이 필요하므로 신뢰할 수 없는 PR을 높은 권한/비밀정보가 있는 runner에서 수행하지 않는다. 가능하면 ephemeral self-hosted runner 또는 격리 컨테이너를 사용한다.
- GitLab은 `artifacts:reports:junit`와 `artifacts:when:always`를 지원한다. **JUnit XML만 생성해도 job이 실패하지 않으므로**, 명령 종료코드를 별도로 유지한다.

### 11.5 CI가 저장할 메트릭

- `targets_total`, `targets_required`, `targets_built`, `targets_selftest_passed`, `targets_executed`, `targets_blocked`
- `cases_replayed`, `cases_fuzzed`, `new_findings_reproduced`, `flaky_findings`, `harness_failures`
- `analysis_seconds`, `build_seconds`, `selftest_seconds`, `fuzz_seconds`, `triage_seconds`
- target별 `compiler triple`, adapter 목록, 계측/실행 모드, 검사 경계.

---

## 12. 보안·배포·운영

- **오프라인 기본:** 클라우드 계정과 API 키 없이 실행.
- **최소 권한:** 타깃 프로세스는 비특권 사용자로 실행, 불필요한 네트워크 egress 차단, 작업 디렉터리 및 쓰기 가능 경로 제한.
- **격리:** Docker/Podman/cgroup 등으로 CPU/메모리/프로세스 제한; honggfuzz의 `ptrace` 요구에 맞게 runner 권한을 **필요한 최소 범위**로 검증한다. 임의로 privileged 컨테이너를 강제하지 않는다.
- **민감정보:** crash input과 stack trace에 기업 비밀정보가 포함될 수 있으므로 artifact 보관 정책은 고객사가 선택한다.
- **라이선스:** honggfuzz Apache-2.0, LLVM 구성요소의 해당 라이선스, Python 패키지 의존성의 NOTICE/SBOM을 확인해 제공한다. 다른 퍼저는 별도 배포/링크 정책으로 다룬다. 저작권 등록과 사용 허가/기술이전 조건은 별도 법률·계약 검토.
- **재현 가능 배포:** 초기에는 버전 고정된 Linux 컨테이너 이미지/설치 스크립트 + 소스 배포, 추후 패키지 제공. 해시를 포함한 toolchain lock 기록.

---

## 13. 예외·실패 모드 표준

| 진단 코드 | 예시 | 조치 |
|---|---|---|
| `E_COMPDB_MISSING` | 컴파일 데이터베이스 없음 | 생성 방법 표시 |
| `E_AST_PARSE` | cross-only 헤더·매크로로 AST 실패 | 원본 플래그와 진단 보존 |
| `E_LINK_GRAPH_UNKNOWN` | 링크 입력/라이브러리 복원 불가 | host target/build 설정 요구 |
| `E_HAL_UNMODELED` | HAL 외부 참조 미해결 | 승인된 adapter 요구 |
| `E_MMIO_DIRECT` | 소스 내 직접 메모리 맵 레지스터 접근 | Blocked 또는 host-specific 분기 필요 |
| `E_ABI_MISMATCH` | 실행 경로에 필수인 구조체/포인터 표현 차이를 보존 못함 | Blocked; 단순 차이는 `ABI_LAYOUT` 경고 |
| `E_ENTRY_UNREACHED` | 하네스는 동작하지만 대상 함수 미도달 | 초기화/진입 경로 재검토 |
| `E_STATE_LEAK` | persistent 실행간 결과 불일치 | isolated로 전환 |
| `E_REQUIRED_NOT_RUN` | CI 필수 타깃 미실행 | exit 2 |
| `E_TIMEOUT_INFRA` | 전체 작업 한계·runner 오류 | 불완전 검사, exit 2 |

`Blocked` 목록 자체는 `scan`에서 정상적으로 표시할 수 있지만, **필수 타깃을 Blocked로 두고 `check`가 0을 반환하면 안 된다.**

---

## 14. 개발 작업 분해 (실제 구현 순서)

### M0 — 기반 계약 (첫 코드 작성 단계)

- CLI skeleton (`doctor/scan/plan/build/fuzz/check/replay/report`), TOML 파서, 결과 schema v1.
- toolchain discovery + build manifest + 샘플 CMake 프로젝트.
- 샘플에 심은 OOB/비정상 포인터 오류를 sanitizer로 재현하는 수동 하네스 경로.

**완료 조건:** 하네스를 수동 제공하더라도 end-to-end CI 통과/실패/재현이 동작한다.

### M1 — 결정적 C 분석/하네스 자동화 (LLVM read-only analysis 병행)

- Clang LibTooling으로 C 함수·타입·call list/전역 의존성 분석.
- bytes+length 후보 탐색, 생성 하네스와 자체 검사.
- 외부 함수/미해결 동작/직접 MMIO 위험을 분류.

**완료 조건:** 실제 C 프로젝트 3개 중 적어도 하나 이상의 **자동 생성된** 타깃을 각 프로젝트에서 성공적으로 실행한다. 실패 타깃은 원인 분류를 남긴다.

### M2 — Host-Lifting P0

- 원본 TU 재컴파일 및 링크 최소 경로 구축.
- 사용자 제공 host target/명시된 외부 함수 adapter 지원.
- 컴파일/링크 차이 및 adapter 계약/ABI 위험 보고.

**완료 조건:** 실제 HAL 의존 C 프로젝트 한 개에서 원본 처리 로직 변경 없이 입력 처리 코드가 동작한다. 필요한 수동 adapter 코드 수를 기록한다.

### M3 — 크래시 검증/CI 안정화

- honggfuzz adapter, 입력 재현, stack normalization, JUnit/JSON, baseline.
- 필수 타깃 실행 보증, 시간 예산/중단/실패 상태, sandbox 문서.

**완료 조건:** GitHub Actions 및 GitLab CI 예제에서 성공/실패/검사 미완료를 명확하게 구분한다.

### M4 — 확장 (M0–M3 안정화 후)

- 제한된 C++17 생성자·RAII·호출 방식 지원.
- 기존 유닛 테스트 setup 재사용, 재빌드 후 하네스 자동 재검증.
- 검증된 persistent mode, 더 정밀한 입력 경계/이벤트 모델.

**완료 조건:** 동일한 C++ 프로젝트의 코드 버전 2개에서 공통 corpus를 재검증하고, 깨진 입력/하네스를 정확히 탐지한다.

---

## 14A. LLVM/하네스 구현 작업 세분화 및 수용 기준 (v0.2 신규)

**W0: LLVM/Clang 분석 계약 (M1 시작 시 병행)**

- `clang -emit-llvm` 재현 가능 여부 확인, compile flags·target triple 보관.
- `fuzzfw-ir-analyze` 최소 read-only New PM 플러그인: call/load/store/inttoptr/volatile/asm 열거.
- AST↔IR linker symbol 및 variant 조인, 조인 실패를 `unknown`으로 유지.
- 완료: 고정 fixture 10개에서 타입·인자·IR 사용/unknown을 구조화된 JSON으로 출력, AST-only fallback 결과 구별.

**W1: 역할 추론 (M1)**

- 입력-길이 쌍 5패턴, signed/narrow length, output-only, capacity, ambiguous pair 각각 fixture 고정.
- 완료: `buf,len` 성공, `output_buf`를 fuzz input으로 오분류하지 않음, 모호한 경우 `adaptable`로 판정.

**W2: 문맥 계획 및 코드 생성 (M1–M2)**

- 독립 C 함수에서 deterministic generated harness 및 `harness_plan.json` 생성.
- 기존 unit-test setup/release 추출은 P1 범위로 유지하고, P0의 단순 함수가 전혀 필요로 하지 않게 구성.
- 완료: 원본 소스 변경 없이 clang host link, 동일 입력에 동일 계획/생성 코드 해시.

**W3: HAL/ABI 검증 (M2)**

- 외부 HAL 함수 참조, 직접 MMIO, arch asm, packed struct fixture.
- 완료: 승인되지 않은 HAL은 `blocked`, 승인 adapter의 prototype/effects mismatches는 빌드 거절.

**W4: 하네스 유효성/CI (M2–M3)**

- G0~G8 게이트 적용, 타깃 미도달·입력 무시·불안정 상태·크래시 구분.
- 완료: 잘못 생성된 하네스는 CI `2`, 재현된 제품 코드 오류는 정책에 따라 CI `1`, 정상 검사는 `0`.

**W5: 실제 사례 (M3)**

- 공개 C 파서 / HAL 기반 펌웨어 / C++ API 후보 각 1개. 범위 밖인 경우 그 이유 포함.
- `time_to_first_fuzz`, 자동 유효 타깃 비율, 수동 adapter LoC, 반복 검증률, confirmed host findings를 평가.
- 완료: 재현 가능한 명령, 소스/빌드 해시, 수동 단계가 모두 문서에 기록.

---

## 15. 테스트 계획과 반례

### 15.1 최소 자체 테스트 고정 집합

| 범주 | 테스트 | 기대 결과 |
|---|---|---|
| Parser | 명확한 bytes+length | 자동 Ready 후보, 스모크 후 fuzzable |
| Parser | 포인터와 길이 불일치 가능한 API | 자동 생성 보류 또는 명시 규칙 요구 |
| Build | 다른 `-D`로 동일 TU 2회 컴파일 | variant 별도 생성 |
| Build | compile DB 있지만 link command 없음 | `E_LINK_GRAPH_UNKNOWN` |
| HAL | 외부 호출 + 승인된 adapter | host executable 실행 |
| HAL | 외부 호출 + adapter 없음 | `E_HAL_UNMODELED` |
| HAL | 함수 내부 inline MMIO | linker wrap으로 우회 성공 처리 금지 |
| C++ | 동일 이름 overload 2개 | 올바른 시그니처 구별 |
| State | static 카운터 누적 | persistent 금지/격리 모드 전환 |
| ABI | `packed`+bitfield가 layout 의존 | `E_ABI_MISMATCH` 또는 경고/Blocked |
| Crash | 의도적 ASan heap OOB | 3/3 재현 + finding |
| Crash | adapter 내부 잘못된 접근 | target finding에서 분리 |
| CI | 필수 타깃 0개 | 비정상 종료 |
| CI | 필수 타깃 blocked | exit 2 |
| CI | 기존 baseline finding 재발 | 정책에 따른 기존 결함 판정 |
| CI | 새 재현 finding | exit 1 |
| CI | corpus가 비었고 실제 입력 미실행 | 검사 미완료(정책상 오류) |
| Rebuild | 함수 시그니처 변경 | 기존 하네스 재검증 실패/재생성 시도 |

### 15.2 실제 코드베이스 벤치마크

- A: 호스트에서 빌드 가능한 C 파서 라이브러리(기본 하네스 생성성)
- B: STM32 계열 HAL 기반 공개 C 예제(호스트 lift와 HAL adapter 수작업)
- C: 제한된 C++17 임베디드 메시지 처리 라이브러리(C++ type/lifetime)

고정 비교군: (1) 개발자 작성 수동 하네스+honggfuzz, (2) 동일 샘플에서 fuzzfw 생성 하네스, (3) 가능하면 기존 공개 자동 하네스 생성 도구. **동일 sanitizer/엔진/코어/시간/seed를 유지**하고, 실행 범위·오탐/미재현·준비 시간 차이를 비교한다.

### 15.3 성공 지표

- 프로젝트별 **최초 유효 퍼징 시작까지 시간**(빌드 준비 포함)
- 사람이 작성한 adapter/harness 코드 라인 수
- `ready / adaptable / blocked` 정확한 분류와 실제 이유
- 필수 타깃 end-to-end 실행 성공률
- 발견 오류의 host 재현율과 target/adapter 귀속 비율
- 빌드 변경 시 재사용 가능한 테스트 비율
- total overhead(분석+빌드+자체 검사)와 실 퍼징 시간 분리

커버리지와 발견한 버그 수는 보조 지표다. **높은 coverage가 실제 입력 도달성을 자동 보장하지 않는다.**

---

## 16. 의사결정 로그 및 미확정 항목

| 항목 | 현재 기본 결정 | 확정 전에 필요한 검증 |
|---|---|---|
| 제품명 | `fuzzfw` | 상표/패키지명 검색 및 등록 가능성 |
| 기본 엔진 | honggfuzz | 실 타깃에서 libFuzzer와 처리량·재현·라이선스 비교 |
| host profile | Linux x86-64 Clang | 실제 ARM cross 환경에서 매크로/ABI 실패 유형 측정 |
| 외부 함수 대체 | 명시적 adapter 및 가능한 링크 wrapper | inline/static/MMIO 경계별 실패 분류 |
| 지원 C++ 범위 | 처음은 제한된 타입·free 함수 | 실제 C++ 객체 생성 난이도 |
| CI baseline | 승인한 기존 finding IDs | 동일 결함의 빌드 변경 시 매칭 정책 |
| 지원 프레임워크 | 특정 RTOS에 종속되지 않음 | 고객사 실제 컴파일/IO/HAL 환경 확보 |

**가장 큰 프로젝트 위험:** 컴파일 정보가 있어도 원본 코드의 *링크와 초기화 조건*을 복원할 수 없을 수 있다. 따라서 분석기보다 먼저 **실제 호스트 빌드와 임베디드 HAL 예제 1개를 끝까지 연결하는 작은 수직 프로토타입**을 만들어 기술적 실현 가능성을 검증한다.

---

## 16A. v0.2 신규 진단 코드

| 코드 | 조건 | 정책 |
|---|---|---|
| `E_IR_UNAVAILABLE` | 분석 IR 생성·분석이 불가능하며 현재 판단에 필수 | `adaptable/blocked`, AST-only 허용 여부 기록 |
| `E_IR_MAP_AMBIGUOUS` | AST 함수 ↔ IR symbol 조인 모호 | 위험한 역할 추론 중단 |
| `E_HARNESS_ROLE_AMBIGUOUS` | 입력/길이/용량/출력 역할 충돌 | 합성 보류, 근거 출력 |
| `E_HARNESS_CONTEXT_UNKNOWN` | 초기화·소유권·수명 근거 부족 | 사용자 wrapper 또는 factory 요구 |
| `E_HARNESS_BUILD` | 생성 하네스 컴파일 오류 | compiler log, artifact 보존 |
| `E_HARNESS_SMOKE` | 정상/경계 입력 자체 검사 실패 | 원인 별도 triage |
| `E_CONTEXT_INVALID` | 검증된 setup/API 사용 계약에 위배 | 하네스 무효, finding 승격 금지 |
| `E_DMA_UNMODELED` | DMA 전송/완료/버퍼 소유권 미모델링 | 해당 경로 Blocked |

---

## 17. 공식 문서 및 학술 근거

다음은 **기존 기술의 실제 동작에 대한 근거**이고, 이 문서의 fuzzfw 관련 모듈·인터페이스는 직접 제안한 설계다.

1. Clang LibTooling — https://clang.llvm.org/docs/LibTooling.html
2. Clang JSON Compilation Database — https://clang.llvm.org/docs/JSONCompilationDatabase.html
3. Clang AST Matchers — https://clang.llvm.org/docs/LibASTMatchers.html
4. CMake compile_commands 지원 범위 — https://cmake.org/cmake/help/latest/variable/CMAKE_EXPORT_COMPILE_COMMANDS.html
5. GNU ld `--wrap` — https://sourceware.org/binutils/docs/ld.html
6. LLVM libFuzzer 문서 — https://llvm.org/docs/LibFuzzer.html
7. Clang AddressSanitizer — https://clang.llvm.org/docs/AddressSanitizer.html
8. Clang SanitizerCoverage — https://clang.llvm.org/docs/SanitizerCoverage.html
9. honggfuzz README / USAGE — https://github.com/google/honggfuzz ; https://github.com/google/honggfuzz/blob/master/docs/USAGE.md
10. ClusterFuzzLite — https://google.github.io/clusterfuzzlite/
11. GitLab JUnit 보고 — https://docs.gitlab.com/ci/testing/unit_test_reports/
12. HALucinator (USENIX Security 2020) — https://www.usenix.org/conference/usenixsecurity20/presentation/clements
13. P²IM (USENIX Security 2020) — https://www.usenix.org/conference/usenixsecurity20/presentation/feng
14. Fuzzware (USENIX Security 2022) — https://www.usenix.org/conference/usenixsecurity22/presentation/scharnowski
15. RTCon (NDSS 2026) — https://www.ndss-symposium.org/ndss-program/symposium-2026/

*문서 한계:* 여기에는 설계 가설과 실험으로 검증해야 할 부분이 포함되어 있다. 모든 논문을 재실험했거나, 특정 고객사의 펌웨어를 실제로 분석했다는 뜻은 아니다.


### v0.2 추가 공식 근거 (LLVM·하네스 합성)

- LLVM, *Using the New Pass Manager*: https://llvm.org/docs/NewPassManager.html
- LLVM, *Writing an LLVM Pass*: https://llvm.org/docs/WritingAnLLVMNewPMPass.html
- LLVM, *Alias Analysis Infrastructure*: https://llvm.org/docs/AliasAnalysis.html
- LLVM, *MemorySSA*: https://llvm.org/docs/MemorySSA.html
- Clang, *SanitizerCoverage*: https://clang.llvm.org/docs/SanitizerCoverage.html
- Clang, *LibTooling*: https://clang.llvm.org/docs/LibTooling.html
- Clang, *Data flow analysis introduction*: https://clang.llvm.org/docs/DataFlowAnalysisIntro.html
- LLVM, *libFuzzer: writing fuzz targets*: https://llvm.org/docs/LibFuzzer.html
- Jeong et al., *UTopia: Automatic Generation of Fuzz Driver using Unit Tests*, IEEE S&P 2023: https://gts3.org/assets/papers/2023/jeong:utopia.pdf
- Zhang et al., *IntelliGen: Automatic Driver Synthesis for FuzzTesting*, 2021: https://arxiv.org/abs/2103.00862

**근거의 성격:** 위 공식 문서와 논문은 제공하는 컴파일러·하네스 메커니즘 및 선행 아이디어를 뒷받침한다. `fuzzfw`의 계획 스키마, 게이트 명칭, 알고리즘 순서, 정책·마일스톤은 이 문서에서 새로 제안한 설계이며 구현·검증이 아직 완료된 것은 아니다.
