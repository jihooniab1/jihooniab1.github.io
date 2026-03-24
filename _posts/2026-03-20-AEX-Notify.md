---
title: "AEX-Notify: Thwarting Precise Single-Stepping Attacks through Interrupt Awareness for Intel SGX Enclaves"
date: 2026-03-13 00:00:00 +0900
categories: [Papers]
tags: [security, side channel, TEE]
permalink: /posts/AEX-Notify/
math: true
---

## Summary for AEX-Notify: Thwarting Precise Single-Stepping Attacks through Interrupt Awareness for Intel SGX Enclaves

## Introduction
Intel SGX는 처음으로 기밀 컴퓨팅에 널리 사용되게 된 상용 TEE 제품입니다. SGX는 유저 공간 메모리에 **enclave** 라는 보호되는 구역을 만들어 높은 권한의 공격자로부터 보호합니다. SGX가 상정하고 있는 강력한 공격자 모델 때문에 여러 공격 연구가 진행되었는데, 높은 권한에서만 사용할 수 있는 프로세서 기능 등을 이용하는 부채널 공격들이 많이 발견되었습니다. OS가 페이지 테이블을 조작하여 트레이스를 알아내는 [Controlled-Channel](https://jihooniab1.github.io/posts/Controlled-Channel/) 공격이 제안되었고, 이런 유형의 공격을 방어하기 위한 여러 기법들이 제안되었습니다.

다른 유형의 공격으로는 APIC와 같은 높은 권한의 하드웨어 인터페이스를 이용하여 명령어 단위 해상도를 통해 부채널 정보를 수집하는 공격이 있습니다. **SGX-Step** 은 APIC 기반의 **single-stepping** 기법을 편리하게 사용할 수 있는 오픈소스 도구를 만들었고, 이를 이용하여 SGX에 대해 많은 수의 **interrupt-driven side channel** 공격이 연구되었습니다. 이러한 공격들은 대부분 SGX-Step의 **deterministic single-stepping** 능력에 크게 의존합니다. 지금까지 제안된 방어 기법들은 모두 **휴리스틱하게** 입터럽트를 감지하여 인터럽트 비율이나 퍼포먼트 모니터링 카운트, 데이터 랜덤화 등에 의존하는데, 이는 인터럽트가 갑자기 자주 발생할 때 오탐을 일으킬 수 있습니다. 게다가 이러한 기법들은 실존하는 하드웨어와 호환되지 않거나 특정 컴파일러, TSX와 같은 CPU 확장을 필요로 할 수 있습니다.

본 연구에서는 실험을 통해 single-stepping을 가능하게 하는 **root cause** 를 확인하였고, 하드웨어 수정만으로는 SGX-Step을 막을 수 없다는 사실을 발견하였습니다. 따라서 `hardware-software co-design` 구조를 제안하였습니다. 하드웨어 측면에서는 Intel SGX의 ISA 확장인 **AEX-Notify** 를 도입하였으며, 이를 통해 enclave가 인터럽트나 예외 발생 시 이를 인지하고 직접 처리할 수 있게 됩니다. 소프트웨어 측면에서는 enclave 내부에 상수 시간 디스어셈블러와 어셈블리 스텁으로 구성된 신뢰된 핸들러를 두어, **다음에 실행될 명령어의 working set을 미리 prefetch** 함으로써 해당 명령어의 실행 속도를 높이고, 타이머가 인터럽트가 해당 명령어 실행 구간에 정확히 맞춰 들어오기 어렵게 만듭니다. 

실험적 증거와 통계적 추론을 결합하여 AEX-noify의 방어 효과를 측정하였고, single-stepping에 의존하는 많은 공격들이 효과적으로 방어될 수 있다고 결론 내릴 수 있었습니다. 논문에서 제안된 ISA 확장은 Intel SGX 명세에 포함되었습니다.

## Background
### Intel SGX
Intel SGX의 enclave는 프로세스 내의 **보호되는 가상 메모리 영역** 으로, 외부 스레드는 enclave 내부의 코드 실행이나 데이터 접근이 불가능합니다. 페이지 테이블은 OS가 관리하지만 **protected enclave page cache map** 으로 무결성을 보호합니다. 단, OS는 present bit, accessed bit, dirty bit 등의 paging control은 여전히 수행할 수 있어 부채널 공격에 악용되었습니다. SGX는 enclave 진입/퇴출 시 TLB를 flush하여 stale 가상 주소 변환으로 인한 보안 침해를 차단합니다.

SGX enclave는 멀티스레드를 지원하는데, 각 스레드는 **thread control structure (TCS)** 를 가지고 있으며 이는 enclave 내부의 고정된 엔트리 포인트를 정의합니다. 스레드는 TCS 중 하나의 주소를 갖고 `EENTER` 명령어를 호출하여 enclave에 진입하고, `EEXIT`을 호출하여 enclave를 나갑니다. SGX SDK는 `EENTER`와 `EEXIT`을 합쳐 **ecall** 이라는 abstraction을 구성하여 일반 코드가 enclave 안의 보호된 함수를 호출할 수 있는 기능을 제공합니다. 반대로 `EEXIT`과 `EENTER`을 합쳐 **ocall** abstraction을 구성하여 enclave가 실행 중에 외부 기능을 사용할 수 있게 합니다. TCS는 단 하나의 고정된 entry point만 허용하기 때문에, enclave 진입 로직은 **레지스터 인자나 내부 상태** 를 확인해서 이게 ecall인지, ocall인지, 예외 처리인지 등을 판단해야 합니다. <br>

![a1](/assets/img/posts/papers/aex-notify_1.png) <br>

또한 SGX enclave는 inter-processor interrupt(IPI), APIC의 타이머 인터럽트, 페이지 폴트 예외 같은 비동기적 이벤트도 처리해야하는데, 이러한 이벤트들은 **Asynchronous enclave exit(AEX)** 를 트리거합니다. AEX는 TCS의 `TCS.CSSA (current SSA)` 필드로 인덱싱할 수 있는 **state-save area (SSA)** 에 현재 프로세서 컨텍스트를 저장하고 TCS.CSSA 값을 증가시킵니다. 이후 외부 소프트웨어가 `ERESUME` 명령어를 호출할 때 TCS.CSSA 값을 감소시키면서 SSA[TCS.CSSA]에 들어있던 컨텍스트를 복원하고, AEX가 발생했던 시점의 실행을 재개합니다. Enclave가 예외를 처리해야할 때는 untrusted runtime이 `EENTER`를 호출합니다. 핸들러는 `SSA[0]`를 확인하고 수정하여 예외를 처리할 수 있고, `EEXIT` 후 `ERESUME`을 통해 enclave application을 재개합니다. `ERESUME`과 다르게 `EENTER`는 TCS.CSSA를 감소시키지 않기 때문에 두 번째 AEX는 컨텍스트를 SSA[1]에 저장합니다.

대부분의 SGX 런타임은 **two-stage exception handler** 구조를 사용합니다. 스레드마다 SSA 프레임을 2개씩 할당하는데, 첫 번째 AEX 발생 시 application의 context가 SSA[0]에 저장되고 TCS.CSSA가 1이 됩니다. 1단계 핸들러는 CSSA=1인 상태에서 실행되며, 추가 예외가 발생하지 않도록 최소한의 작업만 수행합니다. 1단계에서 예외를 처리할 수 없으면 SSA[0]의 내용을 스택에 복사하고 instruction pointer를 2단계 핸들러로 변경한 뒤 EEXIT 후 ERESUME으로 2단계 핸들러에 진입합니다. 2단계 핸들러는 스택을 활용하기 때문에 SSA 프레임 수가 아닌 스택 크기만큼 중첩 예외 처리가 가능하며, enclave application이 등록한 커스텀 핸들러를 호출할 수 있습니다.

SGX는 부채널 공격을 막도록 설계되지 않았으며, 이는 Intel SGX 개발자 가이드에도 명시되어 있습니다. 부채널 공격에 대한 방어는 개발자가 **constant-time programming을 준수하는 방식으로 직접 구현** 해야 하지만, 이는 암호화 외에는 널리 적용되지 않고 있습니다. PRIME+PROBE와 같은 캐시 부채널 공격은 SGX 이전부터 존재했으며, SMT port contention 공격처럼 SGX와 무관하게 모든 실행 환경에 적용되는 공격들도 존재합니다. 따라서 기밀 컴퓨팅 워크로드는 malicious single-stepping으로 증폭될 수 있는 부채널 공격에 취약할 수 있습니다.

### The SGX-Step Framework
SGX-Step은 오픈소스 프레임워크로, 높은 권한의 공격자는 APIC 타이머 인터럽트를 활용하여 `production enclave`를 single-stepping 할 수 있습니다. APIC 타이머 레지스터를 유저 공간에 memory-map 하여 이를 직접 설정하는 것으로, **타이머 설정과 victim enclave 실행(ERESUME) 사이의 코드** 를 획기적으로 감소시켰습니다. SGX-Step은 기본적으로 `one-shot` 모드로 동작하기 때문에, 개발자가 ERESUME 후 실행되는 첫 번째 enclave 명령어에 맞는 타이머 값을 직접 설정해야 하는데, 이는 공격자가 제어하는 debug enclave로 알아낼 수 있습니다.

여러 연구를 통해 SGX-Step이 아주 높은 정확도로 single-step을 하고, 그 외에는 zero-step을 한다는 것을 보였습니다. 이때 CPU는 enclave 명령어가 최소한 하나는 실행되어야 페이지의 A-bit(accessed bit)를 설정하기 때문에, 공격자는 A-bit를 확인하여 zero-step을 걸러내고 single-step만을 골라낼 수 있습니다.

## The Danger of Single-Stepping Attacks
### Interrupt Latency
Single-stepping 도중에는 instruction retirement까지 인터럽트가 지연되기 때문에, 실행되는 명령어에 따라 인터럽트 응답 시간이 달라집니다. `Nemesis` 공격은 SGX-Step으로 수집한 인터럽트 지연 트레이스를 통해 opcode, operand value, cache miss 등 마이크로아키텍처 속성을 유출할 수 있음을 보였고, `Frontal` 공격은 이를 확장하여 store instruction의 정렬(alignment)에 따른 미세한 지연 차이를 연구하였습니다. 두 공격 모두 SGX-Step의 deterministic single-stepping 능력에 크게 의존합니다.

### Interrupt Counting
타이밍 채널과 달리, enclave에서 **실행된 명령어 수** 를 정확히 셀 수 있다면 **단 한 번의 실행만으로도** 아주 미세한 제어 흐름 차이를 결정론적으로 탐지할 수 있습니다. `CopyCat` 공격은 interrupt counting을 페이지 폴트 기반 controlled-channel 공격의 4 KiB 공간 해상도를 극복하는 수단으로 활용하였고, 페이지 접근 사이에 실행된 명령어 수를 세어 여러 암호화 라이브러리에서 키를 완전히 복원할 수 있음을 보였습니다. Van Bulck et al.은 SGX-Step으로 Intel SGX SDK의 문자열 검증 로직에서 `strlen()` 반복 횟수를 정확히 세어 AES-NI 키를 복원하였습니다. 이러한 공격들은 페이지 내부의 극히 미세한 제어 흐름 차이를 탐지해야 하기 때문에, SGX-Step의 deterministic single-stepping 능력에 크게 의존합니다.

### High-Resolution Probing
SGX-Step의 가장 범용적인 활용은 **기존의 부채널 공격을 명령어 단위 해상도로 증폭** 시키는 것입니다. 캐시 부채널 공격의 경우 측정 타이밍이 부정확하면 노이즈가 많아지는데, SGX-Step을 활용하면 명령어 하나가 실행될 때마다 측정할 수 있어 비밀 데이터 접근 패턴을 정확히 파악할 수 있습니다. 브랜치 프리딕터나 x86 세그멘테이션, 부동소수점 예외 등 다양한 부채널에도 같은 방식으로 적용되었습니다.

### Zero-Stepping
타이머 인터럽트나 페이지 폴트를 통해 enclave를 아키텍처적으로 진행시키지 않고 계속 같은 지점에 머물게 하는 **zero-stepping** 기법도 존재합니다. Zero-stepping은 SSA로부터 민감한 CPU 레지스터를 마이크로아키텍처 버퍼로 반복적으로 prefetch하는 수단으로 처음 소개되었고, `MicroScope`는 zero-stepping 도중에도 victim enclave가 transient하게 소수의 명령어를 실행한다는 것을 확인하였습니다. 이러한 transient 명령어들은 아키텍처적으로 커밋되지 않기 때문에 무한히 반복 실행될 수 있고, 단일 아키텍처 실행 안에서 마이크로아키텍처 정보를 다수 수집할 수 있습니다.

## SGX-Step Root Cause Analysis
본 논문에서는 ERESUME 이후 처음 실행되는 enclave 명령어를 **enclave application resumption point (EARP)** 라고 합니다. `ERESUME`은 실행 시간이 길고 비결정적이라 매번 달라지며, EARP에는 모든 x86 명령어가 올 수 있습니다. 따라서 직관적으로는 공격자가 ERESUME 직후의 EARP를 정확히 single-step 하는 것이 불가능해 보입니다. 그러나 본 연구는 실험을 통해 이것이 가능한 근본 원인을 밝혀냈습니다.

### Assisted Page-Table Walk
![a2](/assets/img/posts/papers/aex-notify_2.png) <br>

본 연구에서는 SGX-Step이 성공하는 핵심 이유가 **accessed (A) bit** 에 있음을 지적하였습니다. SGX-Step은 APIC one-shot 인터럽트를 설정하기 전에 victim enclave의 **page-middle directory (PMD)** 의 A-bit를 clear합니다. 이 비트는 zero-step을 걸러내는 데 사용할 수 있지만, **EARP가 PMD A-bit를 설정하는 것** 에는 다른 효과도 존재합니다.

프로세서의 page-miss 핸들러는 `common fast path`를 위해 최적화되어 있고, PMD나 PTE를 수정해야 하는 복잡한 경우에는 훨씬 느린 **microcode assist** 를 사용합니다. 위 그림은 이러한 assist가 수백 사이클 길이의 **assist window**를 열어 EARP 명령어 실행을 길게 만드는 효과가 있음을 나타내고 있습니다. 공격자는 이를 이용하여 높은 정밀도로 APIC 타이머 인터럽트를 설정할 수 있습니다.

SGX는 기밀성과 무결성 보호를 위해 enclave 진입/퇴출 시 **TLB를 반드시 flush** 해야 합니다. TLB가 비워졌으니 EARP 주소를 변환하려면 page-miss 핸들러를 거쳐야 하고, 이때 핸들러가 clear된 A-bit를 발견하면 **microcode assist를 사용하여 비트를 설정** 해야 합니다. 따라서 이 microcode assist는 기존 enclave에서 막을 수 없고, 하드웨어만으로는 SGX-Step을 방어할 수 없습니다.

실험을 통해 assisted page-table walk의 추가 지연을 측정하였습니다. A-bit가 clear된 경우 ($\mu$ = 666, $\sigma$ = 55 사이클)로, assist가 없는 일반 page-table walk ($\mu$ = 27, $\sigma$ = 30 사이클)에 비해 약 25배 더 긴 지연이 발생하였습니다. APIC one-shot 인터럽트 도착 시간은 ($\mu$ = 10,957, $\sigma$ = 73 사이클)의 정규분포를 따르며, 평균을 중심으로 500 사이클 구간 안에서 **99.94%** 의 single-stepping 정확도를 달성할 수 있음을 확인하였습니다.

## Mitigation Objectives
본 논문에서는 하드웨어-소프트웨어 공동 설계인 **AEX-Notify**를 제시합니다. 하드웨어는 Intel SGX에 대한 ISA 확장으로, enclave software가 인터럽트에 대응할 수 있게 합니다. 소프트웨어는 정교하게 조작된 신뢰 인터럽트 핸들러로, 중단된 애플리케이션의 working set을 prefetch하여 EARP가 폴트나 assist 없이 빠르게 실행되게 합니다.

연구의 목표는 **높은 권한의 공격자가 결정론적으로 enclave 명령어를 single-step 하는 것을 방해하는 것**입니다. 방어가 적용되면 공격자가 할 수 있는 공격은 4 KiB 단위 페이지 폴트 공격이나 비결정적인 마이크로아키텍처 공격으로 축소됩니다.

Intel SGX의 표준 공격자 모델을 채용합니다. 공격자는 시스템 설정을 임의로 제어할 수 있고, enclave 실행을 반복하거나 다른 논리 코어에서 동시에 코드를 실행할 수 있습니다. APIC를 통해 인터럽트나 IPI를 enclave에 전달할 수 있으며, OS를 제어하여 Intel SGX 아키텍처 한계 내에서 enclave의 페이지 테이블을 관측하고 조작할 수 있습니다. 이에 따라 공격자는 (i) 4 KiB 단위로 모든 enclave 메모리 접근을 관측하고, (ii) 동일한 페이지에 대한 읽기/쓰기/실행 접근을 구분하며, (iii) 다른 논리 코어에서 enclave의 PTE를 모니터링하여 특정 페이지에 대한 첫 번째 접근 시점을 명령어 단위 해상도로 관측할 수 있습니다.

추가로 enclave 프로그램에 대하여 다음과 같은 가정을 합니다.
- 표준 x86-64 System-V ABI를 따르며, RSP 아래 128바이트의 **red zone** 을 준수합니다. AEX-Notify 활성화 후 RSP는 enclave 내부의 보안 스택을 가리켜야 하며, 공격자는 RSP의 상위 페이지 주소 비트를 알고 있다고 가정합니다.
- 메모리 안전성 버그나 잘못된 명령어를 실행하는 버그가 없습니다.
- enclave 코드와 데이터 페이지는 분리되어 있으며, 공격자는 코드 페이지 내 `RET`(0xC3) 바이트의 위치를 알고 있다고 가정합니다.
- 스레드 간 공유 데이터 접근은 적절히 동기화되어 있습니다.

다음과 같은 목표를 설정하였습니다.
- **G1 (Obfuscated forward progress)**: 공격자가 enclave를 single-step 하거나 zero-step 하는 것을 방지하고, enclave 재진입 후 명령어 단위의 진행 여부를 탐지하지 못하게 합니다.
- **G2 (Bounded leakage)**: 방어 기법이 기존 enclave application보다 더 많은 정보를 유출해서는 안 됩니다.
- **G3 (Software compatibility)**: 방어 기법이 enclave application의 동작을 변경해서는 안 됩니다.
- **G4 (Practicality)**: 정상적인 실행 환경에서 오버헤드가 적어야 하고, 기존 하드웨어에 배포 가능하며, 커스텀 재컴파일 없이 ABI 호환 바이너리에 적용 가능하고, 호스트 소프트웨어와 충돌하지 않아야 합니다.

## The AEX-Notify ISA Extension
AEX-Notify ISA 확장은 encalve가 인터럽트를 인식할 수 있도록 하기 위해 ISA를 최소한으로 변경하여, `ERESUME` 명령어만 수정하고, 새로운 명령어인 **EDECCSSA** 를 추가합니다. 이러한 수정은 마이크로 업데이트로 이뤄질 수 있기 때문에 G4를 만족한다고 할 수 있습니다. <br>

![a3](/assets/img/posts/papers/aex-notify_3.png) <br>

제안된 AEX-Notify ISA는 enclave에 진입할 때 untrusted 소프트웨어가 사용하는 `EENTER` 혹은 `ERESUME`에는 수정을 할 필요가 없으며, trusted runtime이 AEX에 대응할 수 있도록 위 그림과 같이 수정되어야 합니다.
1. Enclave 스레드는 SSA 프레임(SSA[0])의 `AEXNOTIFY` 비트를 1로 설정합니다. 각 SSA 프레임이 개별 enable bit를 가지기 때문에, 핸들러가 실행되는 SSA[1] `AEXNOTIFY=0`으로 유지됩니다. 이를 통해 핸들러 실행 중 인터럽트가 발생해도 ERESUME이 평소처럼 동작하여 핸들러가 중단된 지점에서 재개될 수 있습니다.
2. Enclave 스레드는 AEX가 발생하면, 스레드의 프로세서 컨택스트를 현재 SSA 프레임에 저장하고 TCS.CSSA 값을 증가시킵니다. AEX-Notify는 AEX에 어떠한 수정도 하지 않습니다.
3. 스레드가 `ERESUME`으로 enclave에 진입할 때, **SSA[TCS.CSSA-1]** 의 AEXNOTIFY 비트가 1로 되어 있으면 **ERESUME도 EENTER처럼 동작** 하게 합니다. 즉, ERESUME 명령어가 이전 컨텍스트를 복원하고 TCS.CSSA 값을 감소시키는게 아니라 TCS에 의해 정의된 고정된 엔트리 포인트에서 실행을 재개합니다. Enclave는 진입 시 **TCS.CSSA=1임을 확인하여 AEX-Notify 상황임을 인지** 하고 커스텀 핸들러를 실행합니다(보통은 EENTER하면 TCS.CSSA=0).
4. 핸들러가 완료되면 AEX-Notify에서 새로 도입된 `EDECCSSA` 명령어를 호출합니다. `EDECCSSA`는 TCS.CSSA를 감소시켜 enclave를 탈출하지 않고도 이전 컨텍스트로 복귀할 수 있게 합니다. 기존 방식(EEXIT 후 ERESUME)과 달리 enclave 안에서 바로 전환이 이루어집니다. 단, ERESUME과 달리 `EDECCSSA`는 SSA의 내용을 자동으로 복원하지 않기 때문에, enclave 소프트웨어가 SSA[TCS.CSSA-1]에서 필요한 상태를 직접 복원해야 합니다.

## Enclaved AEX-Notify Software Mitigation
소프트웨어 측면의 핵심은 **동적으로(각 인터럽트 후에)** EARP가 접근할 코드와 데이터 메모리를 식별하고 prefetch 하는 것입니다. **EARP에 점프하기 전에 원자적으로 실행되는 crafted assembly stub** 에 코드와 데이터 페이지를 prefetch 하여, enclave 애플리케이션이 이러한 위치에 접근할 때 CPU 캐시에 hit 될 수 있게 합니다. 그러므로, 적어도 EARP의 첫 명령어는 빠르게 실행될 것이고, 필요로 하는 데이터 역시 fault나 assist 없이 프로세서의 신뢰 TLB로부터 전달될 수 있습니다.

본 연구에서는 소프트웨어 방어 기법을 기존의 **two-stage exception handler design** 을 확장하는 방식으로 구현하였습니다. 1단계 핸들러는 항상 **AEX-Notify 비활성** 상태로 작동하며, SSA[0].AEXNOTIFY를 복사하고 초기화한 뒤 EDECCSSA로 2단계 핸들러로 전환합니다. 2단계 핸들러는 AEX-Notify가 비활성화된 채로 작동하는 non-atomic 부분과, AEX-Notify가 활성화된 채로 작동하는 작은 assembly stub으로 나뉘어져 있습니다. AEX-Notify를 작은 atomic한 부분에만 활성화하여, 핸들러 대부분에서는 인터럽트가 발생하더라도 중단된 지점에서 재개되어 항상 앞으로 진행할 수 있습니다.

1단계 핸들러는 세 가지 작업을 수행합니다. 첫째, 인터럽트된 enclave 앱의 **콜 스택 red zone 아래에 120바이트 공간** 을 예약합니다. 이 공간은 이후 인터럽트가 발생해도 유지되며, assembly stub에서 필요한 레지스터 값들을 저장하는 용도로 사용됩니다. 둘째, SSA[0].AEXNOTIFY를 복사하고 초기화합니다. 셋째, EDECCSSA를 사용하여 enclave를 탈출하지 않고 2단계 핸들러로 전환합니다.

2단계 핸들러는 원래 앱이 AEX-Notify를 사용했는지 확인한 뒤, CTD로 EARP 명령어의 메모리 피연산자를 분석하고, EARP 코드 페이지에서 RET(0xC3) 바이트를 탐색합니다. 이후 assembly stub으로 넘어가 AEX-Notify를 재활성화하고 원자적으로 **working set(EARP가 실행될 때 필요한 메모리 페이지들)** 을 prefetch한 뒤 EARP로 점프합니다.

### Constant-Time Instruction Decoding
본 논문에서는 EARP 명령어의 working set에 대해 다음과 같은 추정을 하고 있습니다.
1. 현재 코드 페이지
2. 현재 스택 페이지
3. (아마도) 그 다음 접근될 데이터 페이지
4. RSP 바로 아래 스택 페이지 (assembly stub 마지막 단계에서 예약 공간의 레지스터 값을 복원할 때 필요)

코드와 스택 페이지는 SSA[0] 프레임을 보고 바로 파악할 수 있지만, 데이터 접근의 경우 EARP의 시멘틱에 기반하여 결정해야 합니다. 이를 위해서는 명령어를 decode 해야 하는데, 이때 퍼포먼스 오버헤드가 최소화 되어야 하고(G4), 방어 기법을 도입하는 과정에서 새로운 부채널이 만들어지면 안됩니다(G2). 기존의 상용 디스어셈블러들은 opcode마다 다른 메모리 접근 패턴을 가지므로 이러한 조건을 만족하기 어렵습니다. 따라서 본 연구에서는 **constant-time decoder (CTD) 를 직접 구현** 하였으며, 조건문에는 `CMOV` 계열 명령어를, 테이블 룩업 가속화에는 `AVX2` 명령어를 활용하였습니다. 퍼포먼스, 구현 복잡도, 정확도 사이의 균형을 위해 false positive는 절대 허용하지 않되(잘못된 메모리 주소에 접근하면 프로그램이 망가지므로), unsupported 명령어에 대한 false negative는 허용하였습니다. Unsupported 명령어는 메모리 접근 없음으로 반환하여 프로그램 정확도를 보장하고(G3), 코드/스택 페이지는 여전히 prefetch되므로 공격자가 악용할 수 있는 경우는 non-stack 데이터 접근이 있는 unsupported 명령어로 한정됩니다. 평가 결과 실제 SGX 바이너리 106개 기준 98% 이상의 명령어 커버리지를 달성하였습니다.

CTD는 SSA[0].RIP가 가리키는 코드 페이지에서 16바이트를 정렬하여 로드합니다. 이때 RIP부터 최대 16바이트까지만 읽되, 페이지 끝에 도달하면 나머지는 dummy 바이트로 채워 경계를 넘지 않도록 합니다. 만약 경계를 무조건 넘어 읽는다면 옆 페이지에서 페이지 폴트가 발생하는지 여부로 공격자가 RIP의 하위 비트를 추론할 수 있기 때문입니다(G2). 

CTD는 로드된 시퀀스를 디코딩하여 메모리 접근 여부, 접근 유형, 타겟 주소를 알아냅니다. 더미 바이트로 패딩된 명령어는 메모리 접근을 하지 않는다고 취급합니다. 핵심은 어떤 명령어가 입력되더라도 메모리 접근 패턴이 달라지지 않도록 하면서 **필요한 메모리 연산자만을 빠르게 디코딩** 하는 것입니다. 타겟 주소를 계산하기 위해, CTD는 먼저 메모리 연산자 수식을 구성한 다음(ex: RAX+0x38), CMOV 기반의 상수 시간 계산을 통해 SSA 프레임 레지스터 정보를 기반으로 계산합니다.

### Verifying Page-Table Permissions
이전에 언급했듯이 높은 권한의 공격자는 x86 페이지 테이블 속성을 제어할 수 있습니다. 따라서 단순히 **EARP의 working set을 read prefetch만 하는 것으로는 부족** 합니다. 공격자가 D(Dirty) 비트를 클리어해두면 EARP가 write 명령어일 때 여전히 microcode assist가 발생하고, XD(eXecute Disable) 비트를 세팅해두면 EARP 실행 시 폴트가 발생하기 때문입니다.

실행 권한 폴트로 인해 enclave가 `zero-step` 되는 것을 방지하기 위해, AEX 핸들러는 EARP 코드 페이지 상의 `RET(0xC3)` 바이트 주소를 atomic하게 실행될 assembly stub으로 전달합니다. 원자적으로 실행하는 과정에서 XD 비트로 인해 폴트가 발생하면, 핸들러가 다시 처음부터 실행되게 됩니다. 이 과정을 빠르게 하기 위해 페이지 주소와 페이지 내 ret 바이트 위치를 매핑해두는 **thread-local C3-cache** 테이블을 만들어 사용합니다. 

EARP가 write 명령어인 경우 두 가지 문제가 있는데, 하나는 공격자가 해당 페이지를 `read-only`로 설정해두었을 때 write 과정에서 폴트가 발생한다는 것이고, 다른 하나는 페이지가 write 가능해도 **D 비트가 클리어되어 있으면 microcode assist가 발생** 한다는 것입니다. Read prefetch만으로는 A 비트만 세팅될 뿐 D 비트는 세팅되지 않으므로, CTD가 write 명령어라고 파악한 경우 아토믹 스텁에서 해당 주소를 **미리 read 후 같은 값을 write back** 하여 두 문제를 모두 해결합니다.

### Atomic Prefetching
본 연구에서 설계한 방어 기법의 제일 핵심적인 부분으로, 정교하게 만들어진 assembly stub을 실행합니다. 핵심은 어떻게 원자적으로 working set을 prefetch하고 EARP로 점프를 하냐입니다(G1). Prefetch와 EARP 점프 사이에 AEX가 발생하면 TLB flush가 발생하면서 prefetch 해둔 것들이 전부 사라지고, EARP 실행 시 다시 microcode assist가 발생하여 landing window가 생기기 때문에 원자적으로 실행하는 것이 중요합니다. Assembly stub은 AEX-Notify가 없는 first mitigation phase와 AEX-Notify가 활성화 되어 있는 **second atomic mitigation phase** 로 나뉘는데, 두 번째 페이즈에서 인터럽트가 발생하면 예외 핸들러가 처음부터 다시 시작합니다. 

Stub은 먼저 마지막 AEX가 enclave 애플리케이션 실행 도중 발생했는지, 아니면 atomic prefetching phase 도중에 발생했는지 확인을 해야 합니다. 후자의 경우 atomic stub이 이미 레지스터를 변경했을 수 있으므로, **중단된 instruction pointer와 파라미터 레지스터를 롤백** 한 후 atomic prefetching phase를 다시 진행합니다. 이 과정 역시 공격자가 mitigation 도중에 인터럽가 걸린 건지, mitigation 후에 걸린건지 구별할 수 없도록 constant-time 방식으로 정교하게 구성해야 합니다(G1). 구현에서는 먼저 SSA[0].RIP 값을 `atomic mitigation assembly code` 영역과 비교하여 확인한 후, `CMOV` 명령어 시퀀스를 통해 스택의 reserved area에서 레지스터를 복원합니다. <br>

![a4](/assets/img/posts/papers/aex-notify_4.png) <br>

Atomic phase는 먼저 `AEX-Notify`를 활성화하는 것으로 시작하여, EARP 명령어 실행 전에 도착하는 인터럽트를 모두 핸들러 시작점으로 리다이렉트합니다. 그 후 working set을 prefetch 하는데, CTD가 write 명렁어라고 알려준 경우, 주어진 위치에서 1 바이트를 읽고 write-back을 합니다. 그 후 반복문을 돌면서 4KiB 크기의 working set 페이지들에 대해 각각 64개의 캐시라인을 전부 로드합니다. 각 페이지마다 돌면서 페이지 전체를 캐시에 올려두어 잠재적인 cache eviction 공격을 방지하는 것입니다. 그 후 기존 AEX가 저장해둔 SSA[0]에 있던 레지스터 값을 복구한 다음, 50% 확률로 짧은 딜레이를 삽입한 후 EARP로 점프합니다. 

## Evaluation
### Security Analysis
#### Confidentiality (G2)
미티게이션이 새로운 사이드채널을 만들지 않아야 합니다. CTD는 상수시간으로 동작하므로 어떤 명령어가 입력되어도 실행 패턴이 동일하고, RIP는 페이지 단위로만 참조하여 하위 12비트가 노출되지 않습니다. 아토믹 스텁에서 수행하는 메모리 접근은 모두 EARP가 원래 수행할 접근과 동일하며, enclave 범위 밖 주소는 역참조하지 않도록 하였습니다.

#### Forward Progress (G1)
공격자가 인터럽트가 미티게이션 도중에 걸린 건지, EARP 실행 이후에 걸린 건지 구별할 수 없어야 합니다. Setup/rollback 페이즈는 CMOV 명령어로 상수시간으로 구현되었으며, 아토믹 스텁은 페이지 경계를 넘지 않도록 정렬되어 있습니다. 랜덤 딜레이는 prefetch 이후에 삽입되어, 딜레이 여부가 페이지 테이블 모니터링으로 노출되지 않도록 하였습니다.

#### Single-Stepping Resilience (G1)
미티게이션의 핵심은 working set을 prefetch하여 EARP의 실행 시간을 최소화함으로써 landing window를 제거하는 것입니다. 이로 인해 공격자는 제한된 window에 맞춰 타이머를 설정하거나, non-stack 데이터 접근 명령어를 찾거나, prefetching을 못하게 하는 방법을 찾아야 합니다. 

먼저 공격자가 아무리 정확한 타이머를 갖고 있다고 하더라도, **ERESUME 시간, 핸들러 시간, 랜덤 딜레이 여부** 에 의해, 타이머를 비결정적인 값으로 맞추는 것은 굉장히 어렵습니다. 두 번째로 CTD가 지원하지 않는 2%의 명령어나 페이지 경계에 걸친 명령어처럼 prefetch가 불완전한 경우를 노릴 수 있지만, 이런 케이스가 실제 secret-dependent 코드 경로에 등장할 가능성은 낮습니다. 세 번째로 공격자가 SMT를 이용해 TLB eviction을 시도할 수 있지만, 아토믹 스텁이 **tight loop으로 반복 prefetch** 를 수행하므로 eviction과 EARP 실행 사이의 시간 창이 너무 좁아 현실적으로 어렵습니다.

### Mitigation Effectiveness Experiments
![a5](/assets/img/posts/papers/aex-notify_5.png) <br>

이 실험에서는 공격자가 더 강력한 타이머로 최선의 값을 설정해도 single-stepping을 하기 힘들다는 것을 보입니다. 벤치마크 enclave에서는 AEX를 활성화한 상태에서 atomic mitigation stub을 진행하고 다음 세가지 타임 스탬프를 측정합니다.
1. $tsc_1$: `ERESUME` 직전에 외부에서 측정
2. $tsc_2$: Mitigation 실행 직전에 내부에서 측정
3. $tsc_3$: EARP가 실행될 때 내부에서 측정

$tsc_2-tsc_1$은 `ERESUME의 latency`를, $tsc_3-tsc_2$는 `mitigation의 latency`를 나타내게 됩니다. 별도의 실험에서 `tsc_3-tsc_1` 값들을 통해 최적의 APIC 설정값을 계산한 후 테스트를 하여도 위와 같이 **EARP 실행 구간은 매우 좁지만, 인터럽트 도착 시간이 넓게 퍼져있어** 성공 횟수가 적은 것을 확인할 수 있습니다. <br>

또한 CTD가 상수 시간으로 동작함을 정적/동적 분석으로 검증하였고, 실제 바이너리에서 98% 커버리지를 달성하였습니다. 

오버헤드의 경우 CTD의 실행 시간은 다른 상용 디코더에 비해 훨씬 짧았고, 인터럽트마다 enclave 재진입 시간이 58% 증가하지만, 정상 환경에서는 인터럽트가 가끔 발생하는 것을 고려하면 실제 오버헤드는 미미합니다. 