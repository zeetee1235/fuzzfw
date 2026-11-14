# fuzzfw

**임베디드 C/C++를 위한 결정적 소스 기반 선택적 호스트 리프팅 퍼징 도구**

`fuzzfw`는 펌웨어 프로젝트에서 **실제로 컴파일되는 코드**를 분석하고, 승인된
하드웨어 경계만 교체하여 Linux 호스트에서 실행 가능한 퍼징 타깃을 구성합니다.
단순히 빌드가 성공했다고 퍼징 가능하다고 판정하지 않고, 대상 함수 도달, 입력
사용, 상태 안정성, 크래시 재현을 별도 게이트로 검사합니다.

> 현재 상태: **pre-alpha (M0/M1 기반)**. Linux x86-64 + Clang 환경에서
> end-to-end 흐름이 동작합니다. honggfuzz adapter는 구현되어 있으나 아직
> 릴리스 매트릭스에서 검증되지 않았습니다.

## 핵심 원칙

- 원본 translation unit을 복사·수정하지 않고 재빌드·재링크합니다.
- `return 0` 같은 자동 HAL stub을 만들지 않습니다. 승인된 adapter와 계약만
  사용합니다.
- 컴파일 성공, 함수 진입, 커버리지 증가만으로 의미적 유효성을 주장하지
  않습니다.
- LLM, 클라우드, 텔레메트리, 자동 네트워크 업로드를 사용하지 않습니다.
- 실패는 명시적으로 처리합니다. 필수 타깃 미실행, 하네스 오류, 환경 오류는
  CI exit `2`로 종료합니다.
- 호스트 ASan 결과는 `HOST_ONLY`이며, 실제 MCU에서 동일 결함이 발생한다는
  자동 증명이 아닙니다.

## 구성

| 구성 | 언어 | 역할 |
|---|---|---|
| CLI / 설정 / 계획 / 빌드 / CI | Go | 단일 바이너리 제어 평면, JSON 계약 |
| Clang AST 분석기 | C++17 LibTooling | 함수·타입·호출·전역·하드웨어 근거 |
| LLVM IR 분석기 | C++17 LLVM API | 읽기 전용 인자 사용·메모리·호출 사실 |
| Replay 런타임 | C11 | 단일 입력, coverage, entry 도달, sanitizer |
| 엔진 | 외부 프로세스 | honggfuzz / libFuzzer / replay |

분석기는 독립 실행 파일이며 버전이 지정된 JSON으로만 통신합니다. 퍼징 루프
안에 Go/Python/RPC/DB가 들어가지 않습니다.

## 빠른 시작

요구사항: Linux x86-64, Go 1.23+, Clang/LLVM 17+, CMake, Ninja.

```sh
make build
# 선택: 네이티브 Clang/LLVM 분석기 빌드 (LLVM 개발 헤더 필요)
make analyzer

cd tests/fixtures/c_clean
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
../../../fuzzfw check --engine replay --time 1s --output fuzzfw-out
```

정상 타깃은 exit `0`. 의도적 결함 fixture는 exit `1`과 함께
`fuzzfw-out/findings/<id>/`에 입력·로그·재현 스크립트를 남깁니다.

```sh
cd ../c_parser
cmake -S . -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build
../../../fuzzfw check --engine replay --time 1s --output fuzzfw-out
```

실제 변이 퍼징은 `--engine libfuzzer` 또는 honggfuzz 도구 체인이 설치된
환경에서 `--engine honggfuzz`로 실행합니다.

## 주요 명령

| 명령 | 역할 |
|---|---|
| `fuzzfw doctor` | Clang, sanitizer, 분석기, 엔진 상태 확인 |
| `fuzzfw scan .` | compdb 가져오기 + 함수 분석 |
| `fuzzfw plan --target NAME` | 하네스/호스트 리프팅 계획과 근거 생성 |
| `fuzzfw build --target NAME` | 하네스 생성 + 원본 TU 빌드 + 자체 검사 |
| `fuzzfw fuzz --time 10m` | 외부 엔진 실행 + 결함 분류/재현 |
| `fuzzfw check --time 10m` | CI용 전체 게이트 |
| `fuzzfw replay FINDING_DIR` | 단일 finding 재실행 |
| `fuzzfw report --input fuzzfw-out/` | Markdown/JSON/JUnit 재생성 |
| `fuzzfw inspect --target NAME` | 역할·제약·adapter·진단 근거 확인 |

Exit code: `0` 통과, `1` 새로 재현된 타깃 결함, `2` 빌드/환경/필수 검사
미완료, `3` 잘못된 설정·사용법.

## 설정 예시

```toml
schema_version = 1

[project]
name = "sensor-firmware"
source = "."
compdb = "build/compile_commands.json"

[ci]
engine = "honggfuzz"
time_seconds = 600
jobs = 2

[[targets]]
name = "sensor_decode"
symbol = "sensor_decode"
source = "src/sensor.c"
header = "include/sensor.h"
input = "bytes_length"
required = true
max_input_bytes = 4096

[[adapters]]
original_symbol = "HAL_UART_Receive"
replacement_source = "tests/fuzzfw/adapters/uart.c"
contract = "tests/fuzzfw/contracts/uart.json"
```

## 현재 구현 범위

구현됨:
- Go CLI/설정/exit code, compdb import, build variant, Git provenance
- 결정적 C/C++ bytes+length 하네스 생성
- 원본 TU 호스트 빌드, ASan/UBSan, sanitizer coverage, replay driver
- 타깃 도달, 반복 안정성, corpus 재생, finding 재현/최소화
- 승인 adapter 계약/prototype 검사, 사용자 wrapper escape hatch
- C++ free function/namespace 함수
- 네이티브 Clang LibTooling AST 분석기, LLVM IR fact extractor
- native 분석기 부재 시 Go AST-JSON/IR fallback
- libFuzzer adapter (통합 테스트), honggfuzz adapter (미검증)
- JSON/JUnit/Markdown 보고, baseline bootstrap

아직 아님:
- C++ class method/객체 factory/RAII 수명 계획
- DMA/ISR/RTOS 이벤트 모델, persistent mode
- New PM AA/MemorySSA 정밀 분석
- 기존 unit test setup 추출
- 다중 타깃 병렬 스케줄링
- 웹 UI/중앙 서버/자체 coverage 엔진

## 보안과 운영

- 기본 오프라인. 원격 전송 없음.
- subprocess는 argv 배열로만 실행하며 shell을 사용하지 않습니다.
- 신뢰할 수 없는 PR 코드를 privileged self-hosted runner에서 실행하지
  마세요.
- ASan의 큰 가상 주소 매핑 때문에 `RLIMIT_AS` 대신 cgroup 기반 메모리 제한을
  권장합니다.
- crash input과 stack trace에 고객 비밀정보가 포함될 수 있으므로 artifact
  보관 정책을 별도로 정하세요.

자세한 내용: [SECURITY.md](SECURITY.md), [보안 모델](docs/security-model.md).

## 라이선스와 상용화

이 프로젝트는 **Apache-2.0**으로 배포됩니다. 상용 사용·수정·재배포·판매가
가능하며, LICENSE와 NOTICE 고지 조건을 지켜야 합니다. LLVM/Clang, honggfuzz
등 외부 도구는 별도 프로세스로 호출되고 각자의 라이선스를 유지합니다.

소프트웨어 등록, 상표, 수출통제, 고객사 계약 검토는
[docs/compliance/README.md](docs/compliance/README.md)를 참고하세요. 이
문서는 법률 자문이 아닙니다.

`fuzzfw`는 작업명이며 상표 등록을 주장하지 않습니다. 회사 명의로 등록하기
전에 `NOTICE`, `AUTHORS.md`, 패키지 메타데이터의 저작권자 표기를 실제
권리자로 갱신해야 합니다.

## 문서

- [아키텍처](docs/architecture.md)
- [빠른 시작](docs/guides/quickstart.md)
- [설정](docs/reference/configuration.md)
- [CLI](docs/reference/cli.md)
- [하네스 합성](docs/harness-synthesis.md)
- [호환성](docs/compatibility.md)
- [CI 연동](docs/ci-integration.md)
- [진단 코드](docs/reference/diagnostics.md)
- [개발](docs/development.md)
- [로드맵](docs/roadmap.md)
- [컴플라이언스](docs/compliance/README.md)
