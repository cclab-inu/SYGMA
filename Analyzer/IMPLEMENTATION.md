# systematic_analysis

Linux x86-64 system calls의 정상 실행 경로에서 반드시 거치는 LSM hook과
도달 가능한 signal checkpoint를 정적으로 분석한다.

## Build

필수 도구는 Go, Clang/LLVM 14 개발 헤더, `llvm-config`, `libclang-cpp`이다.

```bash
cd /workspace/test/systematic_analysis
make
```

`make`는 다음 세 바이너리를 생성한다.

- `systematic_analysis`: 분석 오케스트레이터와 커널 의미 분석
- `clang_kernel_extractor`: Clang AST/CFG 프런트엔드
- `llvm_hook_verifier`: 선택적 LLVM IR 호출 반환값 SSA 검증기

## Kernel Build Input

분석기 코드만 다시 빌드한 경우에는 kernel compile database를 다시 만들
필요가 없다. 다만 최종 인증 실행에는 동일한 `.config`로 끝까지 성공한
kernel build와 그 빌드 직후 생성한 `compile_commands.json`이 필요하다.
부분 빌드에서 만든 기존 database는 사용할 수 없다.

현재 분석 트리와 out-of-tree build 디렉터리를 기준으로 한 재현 가능한
권장 절차는 다음 스크립트로 제공한다. 이 스크립트는 기존 build-tree
`.config`를 보존하지 않고 항상 `x86_64_defconfig`에서 시작한다.

```bash
cd /workspace/test/systematic_analysis
KSR=/workspace/git/linux-v5.15-analysis-src \
KOUT=/workspace/git/linux-v5.15-analysis-build \
JOBS="$(nproc)" \
bash scripts/rebuild_kernel_input.sh
```

Out-of-tree 빌드(`O=...`)는 source tree에 `.config`,
`include/config`, `arch/x86/include/generated` 같은 in-tree 산출물이
남아 있으면 거부된다. 스크립트는 source tree와 build tree에 각각
`mrproper`를 적용한 뒤 config를 새로 만든다. 따라서 기존 build-tree
`.config`와 object는 제거된다.

`make clean`은 `.config`를 제거하지 않는다. 따라서 다음과 같은 조건부
구성은 사용하면 안 된다.

```bash
if [ ! -f "$KOUT/.config" ]; then
  make O="$KOUT" x86_64_defconfig
fi
```

이 패턴은 이전 distribution/allmod 설정을 조용히 재사용하고, 그 결과
`compile_commands.json`에 불필요한 driver/module translation unit이
대량 포함될 수 있다. 특정 배포 커널 config를 의도적으로 분석하는 경우에만
별도 build directory에서 그 config를 명시적으로 복사해 사용한다.

초기 Linux 5.15 태그를 최신 빌드 도구와 함께 사용할 때는 stable kernel에
반영된 호환 수정이 필요할 수 있다. 현재 analysis source tree에는
`memcpy_and_pad` FORTIFY 오탐 방지(`5c4e0a21fae8`), DWC2 long-double
상수 제거(`310780e825f3`), `pahole >= 1.24`의 BTF enum64 생성 방지
(`b775fbf532dc`)를 백포트했다. 이 수정들은 분석 대상 LSM/SIGKILL 경로를
바꾸지 않고 Clang 14와 pahole 1.25 빌드를 통과시키기 위한 것이다.

`all`이 종료 코드 0으로 끝난 뒤에만 database를 생성한다. 최종 분석은
`vmlinux`, `System.map`, module manifest, 각 compile command의 object
output, source/database timestamp와 syscall link symbol을 검사한다.
증분 빌드에서는 관련 없는 config 변경 뒤에도 정상 object가 `.config`보다
오래될 수 있으므로 전역 `.config` 시각만으로 실패시키지 않는다. 대신 해당
object의 Kbuild `.<object>.cmd`에서 실제 `include/config/*` 의존성을 읽어
관련 config 의존성이 object보다 새롭지 않은지 검증한다. 이 metadata가
없거나 관련 의존성이 더 새로우면 입력을 거부한다.
`-allow-incomplete-input`은 빠른 개발 확인용이며 그 실행의 최종 분류는
인증되지 않는다.

## Run

전체 전처리·Clang CFG·호출 해석·선택적 LLVM 사실은 syscall 필터와
독립적인 configured frontend cache로 저장할 수 있다. 최초 한 번은 다음
명령으로 캐시만 준비한다.

```bash
./systematic_analysis \
  -kernel-root /workspace/git/linux-v5.15-analysis-src \
  -compile-db /workspace/git/linux-v5.15-analysis-build/compile_commands.json \
  -frontend hybrid \
  -prepare-frontend-only \
  -preprocess-jobs 4 \
  -clang-jobs 4 \
  -llvm-jobs 2
```

`-frontend-cache auto`가 기본값이며 캐시는
`/workspace/git/linux-v5.15-analysis-build/.systematic-analysis/configured-frontend-v2.gob.gz`
에 생성된다. 이후 syscall별 보고서 실행은 다음처럼 캐시를 필수로
요구한다.

v2 캐시는 canonical 반환 타입, callsite outcome, CFG 지역 변수
초기화·대입, 호출 결과 저장 변수와 address-escape 메타데이터를 포함한다.
현재 extractor는 매크로가 확장된 return 식과 LLVM 전-return 성공 요약도
저장한다. LLVM 요약에는 함수의 모든 반환이 비음수인지뿐 아니라
비양수인지에 대한 보수적 고정점 결과도 포함한다. 기존
`configured-frontend-v1.gob.gz`와 이 메타데이터가 없는 이전
v2 캐시는 재사용하지 않는다. kernel object와 `compile_commands.json`을
다시 빌드할 필요는 없지만, 새 `clang_kernel_extractor`와 cache logic으로
frontend cache는 한 번 다시 생성해야 한다.

```bash
./systematic_analysis \
  -kernel-root /workspace/git/linux-v5.15-analysis-src \
  -compile-db /workspace/git/linux-v5.15-analysis-build/compile_commands.json \
  -out-dir /workspace/test/systematic_analysis/output-hybrid \
  -frontend hybrid \
  -require-frontend-cache \
  -report-jobs 2
```

이 실행은 입력 fingerprint만 다시 확인한 뒤 preprocessing, Clang
extraction, LLVM verification을 건너뛰고 syscall 보고서부터 생성한다.
`-syscalls`가 달라도 같은 cache를 재사용한다. `.config`, compile database,
분석 대상 C/header/generated header, compiler, Clang extractor,
LLVM verifier 또는 configured-frontend 로직 버전이 바뀌면 fingerprint가
달라진다. Go 보고서·분류 로직만 바뀐 새 분석기 바이너리는 같은 frontend
산출물을 그대로 재사용한다. 이전 버전 캐시는 보존된 legacy analyzer
fingerprint가 일치할 때만 한 번 metadata 형식으로 마이그레이션하며,
preprocessing이나 Clang/LLVM 추출은 다시 수행하지 않는다.
`-require-frontend-cache`는 이때 긴 재분석을 자동 시작하지 않고 즉시
실패한다. 의도적으로 다시 만들 때는 준비 명령에
`-rebuild-frontend-cache`를 추가한다. 임의 위치는
`-frontend-cache /path/to/cache.gob.gz`, 비활성화는
`-frontend-cache off`를 사용한다.

최종 실행에서는 `-allow-incomplete-input`을 사용하지 않는다. 입력 검증
결과는 `analysis_metadata.json`과
`reports/input_validation.json`에 기록된다.

특정 system call만 보고서에서 선택하려면 `-syscalls`를 사용한다.
configured frontend cache를 사용하지 않는 첫 실행은 선택된 syscall 수와
무관하게 동일한 compile database 범위를 분석한다.

```bash
-syscalls read,bind,recvmsg,execve
```

LLVM 검증 비용을 제외하고 AST/CFG와 커널 의미 분석만 실행하려면
`-llvm-verify=false`를 추가한다. 기존 텍스트 프런트엔드와 비교하려면
`-frontend legacy`를 사용한다. `-report-jobs`는 syscall 보고서 워커 수다.
LSM 보고서 캐시는 워커별로 독립적이다. SIGKILL 함수 요약은 동일한
allocator·scheduler 하위 경로를 syscall마다 다시 계산하지 않도록 워커가
공유하고, 공유 map 접근과 재귀 요약 생성을 직렬화한다. 따라서
`-report-jobs`를 높이면 LSM 및 전후처리는 병렬화되지만 SIGKILL 증명 자체는
중복 계산과 메모리 폭증을 막기 위해 한 번에 하나만 진행한다. 메모리
사용량도 워커 수와 함께 증가하므로 기본값 2를 권장한다.

실행 중에는 preprocessing, Clang extraction, LLVM verification 이후
syscall별 보고서 시작/완료와 E/N/U 판정이 표준 오류에 출력된다.
하나의 syscall 보고서가 30초 이상 실행되면 `active elapsed=...`
heartbeat도 출력된다. 이 메시지는 해당 보고서가 아직 종료되지 않았음을
보여주며, 실제 전진 여부는 CPU 사용량과 후속 완료 로그를 함께 확인한다.
`classification=clang-cfg-path-value-success-exit`가 실제 E/N/U 분류
엔진이다.
`legacy-raw-signal-states`는 `-emit-raw`로만 실행되는 별도 may-reach
진단 탐색 수이므로 기본 실행에서 0이어도 분류 분석을 건너뛴 것이 아니다.
각 syscall이 끝나면 전체 분류와 proof gap을
`checkpoints/syscalls/<number>-<name>.json`에 원자적으로 기록하고,
`checkpoints/progress.json`의 완료율, LSM/SIGKILL uncertain 비율,
unresolved proof 비율을 갱신한다. 따라서 분석을 중단해도 이미 완료된
syscall 결과는 유지된다.

```bash
jq . output-hybrid/checkpoints/progress.json
```

오래 걸리는 syscall은 다음 항목을 주기적으로 출력한다.

- `states`: 실제로 확장한 `(함수, 상수, ops 제약)` 상태 수
- `dominance-skips`: 더 넓은 기존 상태가 이미 포함해 건너뛴 상태 수
- `dominated`: 뒤늦게 발견한 더 넓은 상태가 대체한 좁은 상태 수
- `transition-cache-hits`: 동일한 함수 전이를 재사용한 횟수

기본 SIGKILL 판정은 `(함수, 상수 인자, ops 제약)`별 DP 요약을 재사용하고,
하나의 정상 성공 exit에서 검문소 우회가 증명되는 즉시 `N`으로 종료한다.
동일한 의미 상태의 경로 대안은 canonical key를 한 번만 계산하여 선형으로
중복 제거하며, 독립적으로 증명된 정상 성공 bypass는 같은 상태의 enforcing
대안보다 우선한다. 함수 하나에서 경로 대안의 곱이 보수적 상한을 넘으면
추측하거나 경로를 버리지 않고
`analysis_state_budget_exceeded/path_state_explosion` proof gap을 기록해
`U`로 처리한다. 따라서 이 실행 안전장치는 거짓 `E`나 `N`을 만들지 않는다.
Clang switch successor의 원래 나열 순서와 무관하게 local effect가 없고,
호출 복잡도가 낮으며 성공 exit에 가까운 CFG block을 먼저 처리한다. 이는
모든 분기를 유지한 채 N witness 발견 순서만 바꾸므로 E/N/U 의미에는
영향을 주지 않는다. 이 탐색 순서 변경은 frontend cache 형식과 무관하므로
기존 cache를 그대로 재사용할 수 있다.
정상 성공 exit에서 `N`이 증명되면 syscall 전체를 즉시 `N`으로 종료한다.
반대로 `E`는 한 경로에서만 흡수 상태로 취급한다. 해당 경로가 이미 유효한
LSM 차단 훅 또는 current-task SIGKILL 검문소를 통과했다면 뒤쪽 호출은 그
경로의 E/N 판정을 바꿀 수 없으므로 도메인별 재귀 분석을 생략하되, CFG
전파는 계속하여 다른 우회 경로와 모든 success exit를 확인한다. 따라서 한
분기의 `E`만 보고 syscall 전체를 `E`로 종료하지 않는다.
`-emit-raw` 진단 모드의 may-reach signal 탐색은 depth 제한으로 경로를
자르지 않으며, 상태 지배 관계로 중복 확장만 제거한다.

## Hybrid Model

1. `.config`는 활성화된 커널 기능을 정의한다.
2. `compile_commands.json`은 각 translation unit에 실제 사용된 include,
   define, target, compiler flag를 제공한다.
3. Clang AST는 함수 정의, 매개변수 타입, 직접 callee, 함수 포인터 호출을
   C 문법과 타입에 따라 추출한다. 각 호출의 반환 타입과 반환값 사용 형태도
   `returned`, `assigned`, `condition`, `argument`, `discarded`, `unknown`으로
   기록한다. typedef 이름만 저장하지 않고 원문 spelling, canonical type,
   `signed_integer`/`unsigned_integer`/`pointer`/`bool`/`void` 분류, 부호와
   bit width를 함께 저장하므로 `pid_t` 같은 typedef도 정수 반환으로
   판정한다. 함수 포인터 인자로 직접 전달된 함수는 callsite별 exact target
   집합으로 기록하고, `const struct ops` initializer도 field별 함수·NULL·
   미해결 상태로 추출한다. 이 AST 사실이 존재할 때만 콜백/ops-table target
   집합을 폐쇄하며 이름 기반 후보 합집합은 인증 증거로 사용하지 않는다.
4. Clang CFG는 죽은 코드를 제외한 reachable 호출, success-only edge,
   block별 호출/훅 이벤트와 지역 변수 초기화·대입을 계산한다. 호출 결과가
   어느 변수에 저장됐는지와 주소가 외부로 노출된 변수도 AST identity로
   기록한다. 짧은 회로 조건식처럼 AST 이벤트를 단일 CFG block에 귀속할 수
   없으면 추측하지 않고 `cfg_event_unplaced`로 남긴다. return 식은 원래
   source spelling과 AST가 확장한 spelling을 함께 보존하므로
   `ZERO_SIZE_PTR` 같은 매크로 반환도 실제 상수 의미로 판정한다. 매크로
   확장 후 callee 이름이 원문에 없더라도, 같은 CFG block에 정확히 한 번
   저장된 callsite 결과와 하나의 success-only true/false edge가 결합되면
   그 edge의 반환 조건을 사용한다. 예를 들어
   `page=__getname(); if (!page) return -ENOMEM;`에서는 확장된
   `kmem_cache_alloc` 결과가 성공 경로에서 non-null임을 복구한다.
   `walk=walk->next=kmalloc(...)`처럼 동일한 포인터를 대상으로 하는 중첩
   대입도 callsite·인자·value-write가 각각 하나로 정확히 대응할 때만
   결과 변수 관계를 복구한다.
   AST가 반환식·대입식·out-parameter 쓰기의 실제 타입과 값 범위를
   `nonnegative` 또는 유효한 객체 주소로 직접 증명한 경우에는 그 사실도
   CFG 값 상태에 보존한다. unsigned 값을 signed 값으로 옮길 때는 목적
   타입이 더 넓어 값 보존이 보장되는 경우만 인정하며, 같은 폭·축소 변환은
   인증하지 않는다. `get_user`·`put_user` 계열은 정확한 매크로 이름과 x86
   확장 결과가 모두 일치할 때만 유효한 사용자 메모리에서 0을 반환할 수
   있다는 존재적 성공 계약을 사용한다.
5. Go 의미 분석은 `if (err) return err`, `ret = -EBADF` 뒤의 success gate,
   retry/goto cleanup처럼 커널 errno 관례가 필요한 부분을 CFG 사실과
   합성한다. 반환값은 negative/zero/positive, null/valid/error pointer,
   true/false의 작은 outcome lattice로 요약한다. 경로 중 재대입이 발생하면
   이전 branch constraint를 폐기하고, 주소가 노출된 변수는 값 추적에
   사용하지 않는다. 자식 함수의 반환 경로는 호출부의 `ret < 0`, `!ptr`,
   direct return, discarded-result 문맥과 교차하고 해당 자식이 요구된
   outcome을 실제로 반환할 수 있음이 재귀 증명된 뒤에만 부모의 정상 성공
   경로에 합성한다. CFG의 callsite ID와 value-write를 이용해
   `ret=alloc(); ret=identity(ret); return ret;` 같은 정확한 호출 결과
   lineage도 보존한다. transformer는 모든 CFG return이 동일 입력
   parameter를 그대로 반환할 때만 identity로 인정한다. 자식의 성공
   outcome은 부모의 실제 결과 변수에 결합하며, 그 변수가 재대입되면
   폐기한다. 따라서 자식의 `ret == 0` 증거와 부모의 `ret != 0` 분기를
   같은 경로로 합치거나, 무관한 호출 성공으로 다른 반환 변수를 성공으로
   인증하지 않는다. alias 또는 forwarded return의 성공 증명도 현재 CFG
   경로가 요구하는 outcome과 LLVM이 증명한 함수 전체 반환 범위를 먼저
   교차한 뒤 동일 outcome의 자식 실행을 재귀 증명한다. 서로 다른 실행에서
   얻은 `zero`와 `nonzero` 증거를 하나의 성공 경로로 합성하지 않는다.
   `error=len` 같은 단순 지역 변수 alias도 CFG write로
   보존하되 원본이나 alias가 다시 쓰이면 즉시 무효화한다. 고정 폭 unsigned
   지역 변수를 더 넓은 signed 반환형으로 변환할 때만 비음수 outcome을
   인정하며, 동일 폭 변환이나 shadowing이 있는 선언은 인증하지 않는다.
   `ERR_PTR(x)`는 `x`의 정확한 부호를 아직 증명하지 못했더라도 kernel error
   pointer 계약상 error pointer로 제한한다. 단, source가 명시적으로
   `ERR_PTR(0)`을 사용한 경우만 NULL로 구분한다. `PTR_ERR`·`ERR_PTR`·
   `ERR_CAST`의 입력은 현재 경로에서 추적 중인 동일 변수일 때만 exact
   symbolic relation으로 유지한다. 반환 변수와 성공 분기를 결정하는
   변수까지의 단순 alias 의존성만 역방향으로 보존하여, 통계·debug 같은
   무관한 write는 proof cone에 포함하지 않는다. CFG successor가 오직
   성공 requirement와 양립할 수 없는 정확한 반환값으로만 끝난다는 것이
   증명된 경우에만 failure-only branch로 제거하며, cycle이나 unknown
   return이 하나라도 있으면 제거하지 않는다.
   일반 callee의 실패값도 정확한 Clang callsite에 주입해 이후 대입, 조건,
   goto와 return을 따라간다. 모든 feasible 반환이 오류이면 차단 전파,
   모든 feasible 반환이 성공이면 오류 흡수로 판정한다. 두 종류가 섞이거나
   cycle·불명확한 write·보존되지 않은 pointer escape가 있으면 추측하지
   않고 `U`로 남긴다. out-parameter는 자식 함수의 해당 pointer가 다른
   호출로 escape하지 않고 모든 관련 반환 경로의 쓰기가 닫혀 있을 때만
   반환 outcome과 결합한다.
6. LSM/SIGKILL proof cone과 직접 훅·검사를 포함한 translation unit을
   선택적으로 LLVM IR로 다시 생성한다. 훅뿐 아니라 일반 직접 호출도
   SSA상 반환값이 분기·함수 반환에 쓰이는지 또는 완전히 무시되는지 기록한다.
   또한 child의 음수 오류, 0·양수 성공값, valid pointer 성공값이 wrapper의
   반환까지 보존되는지를 모든 LLVM return 경로에서 검증한다. 0 또는 양수
   중 한 outcome만 보존돼도 child가 그 outcome을 반환할 수 있음을 별도로
   증명한 경우에는 존재적 정상 성공 증거로 사용할 수 있다. 성공값 보존
   사실은 동일한 source callsite와 일치하고 CFG cycle을 가로지르지 않을
   때만 함수간 성공 증명에 사용한다. 호출자가 전달한 symbolic parameter는
   자식의 모든 관련 return이 그 parameter를 그대로 반환하고, 현재 CFG
   제약과 성공 requirement가 모순되지 않을 때만 존재적 성공 witness로
   바인딩한다. 함수의 모든 LLVM 반환이 비양수임이 증명되면
   `if (ret) return ret`의 참 분기에서 가정하던 가상의 양수 성공을
   제거하고 0인 정상 진행 경로만 남긴다.

추가 proof-cone 축약은 Clang CFG가 완전하고, 직접/간접 호출의 합집합을
재귀적으로 닫을 수 있을 때만 수행한다. 관련 LSM 또는 signal 효과가 전혀
없는 함수는 syscall 도달 가능 호출 그래프의 고정점으로
`closed_effect_source_absence` 요약한다. source가 없는 재귀 SCC는
`None`으로 수렴하지만, SCC 안이나 그 하위에 실제 훅·검사 또는 미해결
효과 간선이 있으면 각각 `Possible` 또는 `Unknown`이 역전파된다. 따라서
단순 cycle 자체는 더 이상 불확실성의 근거가 아니며, 미해결 target과
배치할 수 없는 관련 CFG 이벤트는 음성 요약으로 지우지 않는다.
호출 결과가 최종 `return wrapper(..., result)`로 전달되는 경우도 wrapper의
모든 반환과 `result` 매개변수 변경이 동일 오류 또는 명시적 음수 오류임을
확인할 때만 interprocedural 전파로 인정한다.
호출 반환값이 무시됐다는 음성 요약은 Clang AST가 호출을 독립된 expression
statement 또는 `void` 반환으로 분류하거나, 동일한 reachable AST 호출 수를
포괄하는 LLVM SSA 사실이 모두 `ignored`일 때만 사용한다. `if`, `while`,
short-circuit, 비교식 안의 호출은 반환 사용 여부를 추측하지 않는다. `if` 기반 양성
전파도 호출이 비부정 조건을 직접 구성함을 증명하며, `&&`의 추가 조건은
`conditional`로만 취급한다.
관련 효과가 없는 호출도 반환값이 caller 성공 여부를 결정하면 완전히
삭제하지 않고 정확한 callsite outcome 제약을 남긴다. LLVM의
zero/positive/valid-pointer 보존 사실은 해당 child outcome이 caller 성공에
충분하다는 증거로만 사용하며, 그 사실과 겹치지 않는 다른 child outcome을
불가능한 경로처럼 제거하지 않는다. 특히 `nonnegative`처럼 여러 atomic
outcome을 포함한 존재적 성공 요구는 자식이 실제로 독립 증명한
`zero`·`positive` outcome으로만 부모에 투영한다. 넓은 요구 자체를 정확한
자식 반환값처럼 저장하거나 이후 분기에서 임의로 좁혀 가상의 bypass를
만들지 않는다.

Allocator/reclaim처럼 느린 경로만 signal checkpoint를 포함하는 함수는 함수
이름으로 제외하지 않는다. 완전한 CFG에서 관련 훅·검사가 없는 block만
따라가고, 호출부가 요구한 non-null/zero/nonnegative 반환 outcome까지
도달하는 경로가 증명될 때만
`cfg_effect_free_fast_success_path`로 축약한다. 열린 함수 포인터, 배치되지
않은 관련 이벤트, 재귀 경로, 불명확한 반환 조건을 만나면 fast-path 증명을
포기하고 기존의 엄격한 U 판정으로 돌아간다. 반환값이 해당 callsite에서
Clang에 의해 `discarded`로 확정된 호출은 그 자식의 오류/abort 반환이
syscall 결과를 통제할 수 없으므로 proof cone에서만 제거한다.
예외적으로 kernel core의 fallible allocator API는
`include/linux/slab.h` 또는 `mm/`에 있는 정확한 함수 이름과 non-null valid
pointer 요구조건이 모두 일치할 때만 명시적 runtime-resource contract를
사용한다. 이 계약은 가용 메모리와 allocator fast path가 존재하는 실행에서
LSM hook 또는 current-task SIGKILL checkpoint 없이 성공할 수 있다는
존재적 증명이며,
`kernel_fallible_allocator_effect_free_fast_path_contract`로 proof path에
노출된다. lookalike 이름, 다른 파일, NULL/error-pointer 요구조건에는
적용하지 않는다.
x86 `mm_pkey_alloc`은 구현이 명시한 `-1` 실패 sentinel과 nonnegative 성공
계약을 exact 함수·파일에 한해 사용한다. caller의 success-only CFG edge가
`pkey == -1`을 배제할 때만
`kernel_minus_one_sentinel_success_contract`를 적용한다.
검문 결과가 지역 함수에서 `NULL`, `false`, `ERR_PTR` 또는 음수 errno로
종료되는 경우에는 반환 타입에 맞는 실패 인코딩을 기록한다. 부모 호출부가
그 인코딩을 실제 오류 종료로 변환하는 경우에만 current-task SIGKILL
효과를 syscall 종료까지 전파한다.

SIGKILL E/N/U 판정에는 텍스트 파서의 결과를 Clang may-reach 사실만으로
승격하지 않는다. 완전한 CFG에 배치된 이벤트와 검문 결과의 syscall 종료
전파가 함께 증명된 경우만 `E`로 채택한다.
LSM은 예외적으로 `ret=-EBADF` 후 성공 분기에서만 `ret`을 덮어쓰는 커널
errno/goto success-gate를 의미 분석하고, 각 호출이 Clang reachable이며
훅 오류가 syscall까지 전파됨을 별도로 증명한 경우에만 보조 증명으로 쓴다.
translation unit별 함수 의미 변형은 Clang ODR semantic hash로 분리해
추출하며, 서로 다른 variant가 합쳐지면 `frontend_variant_conflict`로
표시하고 인증하지 않는다.

CFG가 정상 성공 우회처럼 보이는 경로를 만들더라도, 그 경로가 실제로는
하위 함수의 실패 인코딩 때문에 성공할 수 없다는 독립 증명이 있으면 해당
`N` witness를 폐기한다. 이 교정은 훅이 BPF LSM에 매핑되고, 훅의 오류가
연산과 syscall을 모두 종료하며, 자식의 실제 실패 인코딩
(`negative errno`, `ERR_PTR`, `NULL`, `false`)이 호출자 경계를 거쳐
보존되고, Clang proof path가 완전할 때만 적용한다. 일부 allocator/file
생성 wrapper처럼 일반 규칙만으로 인코딩을 복구하기 어려운 경우에는 정확한
함수명, source path, CFG 완전성, callsite 수와 body 형태를 모두 확인하는
reviewed kernel contract를 사용한다. 조건 하나라도 달라지면 contract를
적용하지 않고 결과를 `U`로 되돌린다. 적용된 근거는
`lsm_error_effects[].proof_method`와
`lsm_path_coverage.proof_methods`에 각각
`reviewed_kernel_success_gate_contract` 또는
`kernel_gate_invalidates_cfg_bypass`로 기록된다.

구조체 멤버가 callback이나 하위 함수에서 바뀔 수 있는 escaped aggregate,
런타임 등록 함수 포인터, 열린 ops-table target, 전역 상태 불변식은 단순
소스 대입만으로 닫지 않는다. 예를 들어 aggregate의 생략 초기화가 0이어도
그 주소가 하위 호출로 전달된 뒤의 멤버 값은 memory-effect가 폐쇄되지
않으면 계속 `U`다. 이는 구현 공백을 줄이기 위해 alias를 임의 가정하여
거짓 `E` 또는 `N`을 만드는 것을 방지한다.

LLVM 결과는 source-level proof를 보강하는 증거다. 직접 반환 전파처럼
source-level 증명이 이미 있는 경우는 corroboration으로 사용하고, LLVM의
may-use 사실만으로 새로운 양성 집행 증명을 만들지 않는다. 일반 호출의
`ignored` 사실도 AST 호출 개수와 일치할 때만 음성 slicing에 사용한다.
최적화나 inline으로 원래 함수에 훅 이름이 남지 않으면
`not_present_after_codegen`이며, 이는 미사용 증거가 아니라 `unknown`이다.
`call_int_hook(..., 0, ...)`처럼 source에 명시된 default-allow 반환은
해당 함수의 존재적 성공 witness로 사용할 수 있지만, 음수 default나 여러
서로 다른 return이 섞인 wrapper에는 적용하지 않는다.

## Soundness Policy

인증 결과는 지정한 kernel tree, architecture, `.config`,
`compile_commands.json`, 정적으로 인덱싱된 built-in/module 집합에
한정된다. 양성 증명에서 미해결 alias, 함수 포인터 target, CFG 이벤트,
translation-unit variant는 유리하게 가정하지 않는다. 음성 증명도
signal/LSM 오류가 syscall 종료에 영향을 줄 수 있는 proof cone이 완전히
닫힌 경우에만 생성한다.
앞서 명시한 core allocator fast-path처럼 별도로 열거된 kernel semantic
contract는 이 입력 환경에서 가능한 실행을 정의하는 분석 가정에 포함되며,
결과의 proof method에 반드시 표시한다.

따라서 지원하지 않는 의미는 `uncertain`으로 보내는 precision-first
정책이다. 이는 분석기가 명시한 C call/return 및 kernel errno 의미 범위의
soundness 주장이지, inline assembly, undefined behavior, 동적 코드 변경,
컴파일러 결함까지 포함한 수학적 “절대 0 FP” 주장은 아니다.

## Key Output

- `summary.json`: syscall별 must-pass hook, signal checkpoint, errno 효과
- `checkpoints/progress.json`: 실행 중 누적 분류와 unresolved 비율
- `checkpoints/syscalls/*.json`: 완료 즉시 저장되는 syscall별 전체 결과
- `function_index.json`: 전체 AST/CFG/LLVM 진단 인덱스. 기본적으로 만들지
  않으며, 상세 프런트엔드 디버깅이 필요할 때만
  `-emit-function-index`를 지정한다. Linux 전체 분석에서는 수 GB가 될 수
  있지만 최종 E/N/U 분류에는 필요하지 않다.
- `analysis_metadata.json`: 프런트엔드/CFG/LLVM 적용 범위와 충돌 수
- `reports/input_validation.json`: config/build/database/object 입력 검증
- `reports/syscall_availability.txt`: linked kernel의 syscall slot 가용성
- `reports/effective_lsm_syscalls.txt`: 개별 경로에서 오류 차단 효과가 증명된 훅
- `reports/certified_bpf_lsm_syscalls.txt`: 최종 인증된 syscall과 BPF hook 이름
- `reports/lsm_path_coverage.txt`: 성공 exit별 E/N/U coverage와 집행 훅 집합
- `reports/sigkill_path_coverage.txt`: 성공 exit별 E/N/U coverage, 검문소, 우회 증거
- `reports/unproven_lsm_candidates.txt`: 정상 경로 함수에서 발견됐지만 필수성이 미증명인 훅
- `reports/lsm_classification.txt`: syscall별 최종 BPF LSM 집행 가능성 분류
- `reports/sigkill_classification.txt`: syscall별 최종 current-task SIGKILL checkpoint 분류
- `reports/classification_counts.json`: unavailable을 분리한 최종 논문용 개수
- `reports/proof_gaps.txt`: 분류를 막은 CFG, alias, 함수 포인터, 미해결 호출 근거
- `reports/proof_gap_categories.json`: domain별 gap을 구현 개선 가능,
  설정 입력 모호성, 분석 정밀도 한계, 본질적 정적 분석 한계로 집계
- `reports/llvm_verification_failures.txt`: IR 생성 또는 검증 실패 목록

`effective_enforcing_lsm_hooks`는 해당 경로에서 오류가 syscall까지
전파되는 개별 훅이다. 최종 분류는 `lsm_path_coverage`를 사용한다.
이 값은 각 CFG 성공 경로를 `E`(집행), `N`(비집행), `U`(미해결)로
전달해 합성하므로, 서로 다른 분기가 서로 다른 훅을 지나더라도 모든
성공 exit가 `E`이면 인증할 수 있다.
`success_path_hook_sets`와 `success_path_check_sets`는 실행된 이벤트의
전체 목록이 아니라 각 `E` 경로를 증명하는 최소 witness 집합이다. 이미
집행이 증명된 경로에서는 훅 또는 검문소 하나만 남겨도 E/N/U 의미가
같으므로 중복 조합을 제거한다. 자식 함수의 지역 CFG block 제약은 함수
경계에서 제거하지만, 증명된 반환 outcome은 정확한 부모 callsite와 결과
변수 제약으로 변환한다. 직접 `return child()`와 LLVM이 모든 반환 경로의
성공 보존을 증명한 callsite만 결과 변수와 무관한 부모 성공 witness가 될
수 있다.

## Final Classification

`summary.json`의 `lsm_classification`은 다음 셋 중 하나다.

- `certified_bpf_lsm_enforceable`: `certified_enforcing_lsm_hooks` 중 하나가 모든
  정상 성공 경로를 단독 또는 다른 인증 훅과 함께 덮고, BPF LSM의 음수
  반환이 연산과 syscall을 차단한다는 증명이 성립한다.
- `certified_bpf_lsm_not_enforceable`: 적어도 하나의 feasible 정상 성공 경로가
  모든 유효 훅을 우회하거나 훅 반환값이 syscall 종료에 사용되지 않음이 증명된다.
- `uncertain`: CFG, alias, 함수 포인터, translation-unit variant 또는 오류
  전파 분석 공백 때문에 양쪽 결론을 확정할 수 없다.

보편 집행의 합성 규칙은 `E+E=E`, `E+N=N`, `N+U=N`, `E+U=U`다.
즉 하나의 완전하고 feasible한 정상 성공 경로에서 비집행이 인증되면,
다른 경로에서 E 훅이나 검문소를 찾았더라도 syscall 전체 분류는 항상
`N`이다. `N`은 단순한 구문 분기가 아니라 CFG의 정상 성공 exit에 도달한
우회 witness가 있을 때만 생성된다. 이 witness는 `return 0` 같은 명시적
성공 반환이거나, 정상 성공이 재귀적으로 증명된 함수를 그대로 `return`하는
경우여야 한다. 오류 경로와 성공 경로가 `return err`로 합쳐져 반환값을
구분할 수 없으면 N으로 추측하지 않고 `U`와 `unproven_bypass_path`로 남긴다.
전처리 상수와 함수 인자 상수로 거짓인 분기는 먼저 제거한다. 모든 분기 뒤의
공통 `E`는 각 경로가 실제로 그 E를 지난다는 뜻이므로 앞선 N/U를 덮을 수
있지만, common E 자체를 우회하는 인증 성공 경로가 하나라도 있으면 N이
우선한다.

`-EBADF`, `-EFAULT` 같은 훅과 무관한 선행조건 실패 경로는 정상 성공
경로의 E/N 투표에서 제외한다. 반대로 BPF LSM 훅의 음수 반환이나
current-task SIGKILL 검문 결과 때문에 새로 발생한 오류 종료는 제외하지
않는다. 그 오류가 연산을 차단하고 syscall까지 전파됨이 증명되면 해당
검문소의 `E` 증거다.

`sigkill_classification`도 동일한 보편 집행 의미를 가지며 다음 셋 중 하나다.

- `certified_sigkill_enforceable`: 모든 feasible 정상 성공 경로가 current-task
  SIGKILL 검문소를 지나며, 검문 결과가 syscall 종료까지 전파된다.
- `certified_sigkill_not_enforceable`: 하나 이상의 feasible 정상 성공 경로가
  검문소를 우회하거나 검문 결과가 syscall 종료에 사용되지 않는다.
- `uncertain`: E도 N 우회 witness도 확정하지 못한 경로가 남아 있다.

논문용 단일 문자는 `lsm_enforcement_state`와
`sigkill_enforcement_state`의 `E`, `N`, `U`이며 unavailable slot은 `NA`다.

syscall table에는 이름은 있지만 설정상 구현이 빠진 slot도 포함한다.
완성된 `System.map`에서 weak ENOSYS stub 또는 빈 table slot으로 확인된
항목은 두 domain 모두 `not_applicable_unavailable`이며, uncertain 비율의
분모에서 제외된다.

`proof_eligibility.<domain>.status`는 `complete`, `positive_only`,
`incomplete` 중 하나다. `positive_only`는 개별 양성 witness는 인증됐지만
주변 cone이 닫히지 않아 음성 결론에는 사용할 수 없다는 뜻이다.
`unresolved_edges_in_proof_cone`은 이 판단의 함수·간선별 근거이며,
`negative_reasons`는 최종 음성 또는 미확정 판정의 요약이다.
각 unresolved edge의 `category`는 원인 종류이고 `resolution_scope`는
`implementation_improvable`, `configured_input_ambiguity`,
`analysis_precision_limit`, `static_analysis_limit` 중 하나다. 따라서
구현 공백과 런타임 함수 포인터/subject alias 같은 정적 분석 한계를 논문
통계에서 분리할 수 있다.

SIGKILL 최종 분류에는 인자가 명시적으로 `current`로 증명된 검사만 사용한다.
동일 함수에 같은 검사 함수 호출이 여러 개 있어도 Clang callsite ID별로
state mask, task subject, local errno 효과를 분리하며 다른 callsite의
증거를 빌려오지 않는다.
`blocks_operation=guaranteed`, `terminates_syscall=guaranteed`이고 필수
경유까지 증명된 경우만 mandatory다. `!ret && signal_pending(current)` 뒤의
명시적 음수 errno 대입처럼 검사와 중단의 결합이 직접 증명되면
`abort_effect=conditional`로만 인증한다.
`return signal_pending(current)`처럼 boolean 값을 그대로 전달하는 경우는
errno 중단으로 해석하지 않으며, 명시적 음수 오류/재시작 값으로 정규화되는
경로만 양성 증명에 사용한다.
반대로 `while (!signal_pending(current))`처럼 loop 종료와 errno 반환을 함께
증명해야 하는 패턴은 아직 자동 승격하지 않고 `uncertain`으로 남긴다.
단순 allocator/reclaim/debug 도달성처럼 검사 함수의 반환이 호출자에게
무시되는 경로는 proof cone에서 제거한다. 함수 포인터 경로는 단일 후보
target만으로 인증하지 않는다.

`reachable_signal_checks`, `current_task_reachable_signal_checks`는 검사의
존재/도달성 진단값이므로 그 자체가 checkpoint 인증은 아니다.
`signal_check_paths[].abort_effect`의 `guaranteed`/`conditional`과 최종
`sigkill_classification`을 함께 확인해야 한다.
예를 들어 `kill(2)`의 신호 수신 대상 검사처럼 임의의 task를 검사하는 경로는
`subject=other-or-unknown-task`로 남고 current-task checkpoint로 승격되지 않는다.
LSM 분류는 분석 대상 `.config`에서 `CONFIG_SECURITY`,
`CONFIG_BPF_SYSCALL`, `CONFIG_BPF_LSM`과 기본 `CONFIG_LSM`의 `bpf` 활성화를
확인한다. 실제 부팅 커널은 `/sys/kernel/security/lsm`도 별도로 확인해야 한다.
