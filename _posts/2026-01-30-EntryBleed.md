---
title: "EntryBleed: A Universal KASLR Bypass against KPTI on Linux"
date: 2026-01-30 00:00:00 +0900
categories: [Papers]
tags: [security, side channel, linux]
permalink: /posts/EntryBleed/
math: true
---

# Summary for EntryBleed: A Universal KASLR Bypass against KPTI on Linux

## Introduction
2018년 Meltdown, Spectre 공격이 발견되면서 마이크로아키텍처 취약점이 주목받기 시작했습니다. 이 공격들은 프로그래밍 에러가 아닌 퍼포먼스 최적화를 위한 하드웨어 설계에서 비롯된 것으로, 대부분 부채널 공격으로 이어집니다. 실행 권한이 없는 instruction의 경우 하드웨어 롤백 메커니즘이 존재하지만, 마이크로아키텍처 상태까지 되돌리는 데에는 실패하기 때문에 의도하지 않은 side effect가 남게 됩니다.

이러한 side effect로부터 암호키, secure enclave content 등의 비밀 데이터가 유출될 수 있는데, 그 중 KASLR 레이아웃은 커널 하드닝의 핵심 요소로서 특히 중요합니다. Meltdown 이후 이를 방어하기 위해 KPTI가 도입되었지만, 본 논문의 EntryBleed 공격은 KPTI가 적용된 환경에서도 **TLB에 남아있는 커널 가상 주소** 를 통해 KASLR을 우회할 수 있음을 보여줍니다.

### KASLR Security
KASLR은 코드, 힙, 스택을 비롯한 커널 메모리 지역의 레이아웃을 재부팅할 때마다 랜덤화하는 보안 기법입니다. Meltdown은 커널과 유저 공간 간의 **공유된 페이지 테이블 구조** 에 의존하는데, 요청된 가상 주소가 MMU에 의해 변환이 될 수 있는 한 투기 실행, 비순차 실행을 통해 권한이 없는 instruction들도 실행이 될 수가 있습니다. 이를 해결하기 위해 **KPTI** 기법이 도입되었는데, 이는 커널 PTE와 유저 PTE를 분리하여 커널과 유저 공간 사이를 오가려면 OS는 **top-level page table pointer** 를 바꿔주어야 합니다. 많은 운영체제들이 KPTI를 하드닝 기법으로 활용하고 있기 때문에, KPTI의 결함으로 인해 KASLR이 무력화 될 경우 심각한 문제가 될 수 있습니다.

### EntryBleed
본 연구에서는 유저 공간과 커널 공간 간의 격리가 충분하지 못한 Linux KPTI의 결함을 발견하였습니다. 예외, 인터럽트, 시스템 콜 등을 처리해야 하기 때문에 유저 모드일 때 사용되는 페이지 테이블에도 커널 코드로 오가는 통로 역할을 할 수 있는 소수의 커널 주소 조각들이 남아있습니다. 이걸 **트램폴린 지역(trampoline region)** 이라고 부르는데, 이 트램폴린 지역이 마이크로아키텍처 KASLR 우회의 유출 통로가 될 수 있다는 가설을 바탕으로 **prefetch-based side channel** 공격을 확장시켜 KALSR을 우회할 수 있었습니다. 별도의 튜닝이 필요하지 않고 1초내로 공격이 작동합니다.

본 연구에서는 물리 호스트와 하드웨어 가속된 VM 두 환경에서 모두 공격이 작동하는 것을 확인하였습니다. Kernelspace에서 Userspace 코드로 돌아가기 직전에 TLB는 트램폴린 주소에 대한 페이지 변환 정보를 캐시합니다. 이후 사용자 공간에서 **prefetch side channel** 을 이용하여 TLB 상태를 관측하여 KASLR 레이아웃에 대한 정보를 알아낼 수 있습니다. 나아가서 **virtualized MMU에 대한 현대 ISA의 최적화** 로 인해 마이크로아키텍처 side-effect가 어떻게 게스트-호스트 컨텍스트 스위치를 거쳐도 남게 되어 EntryBleed 공격이 하드웨어 가속 VM 환경에서도 동작한다는 것을 실험을 통해 알아낼 수 있었습니다. 본 연구에서 VM 관련 분석의 범위는 KVM 하이퍼바이저 환경에서 사용되는 Intel VT-x 확장에 초점을 맞추며, MMU 최적화 기술인 EPT, VPID, shadow paging을 중점적으로 다룹니다. 

## Background
### Virtual Memory and Paging
프로세스 격리, 메모리 최적화 등을 위해 대부분의 운영체제는 **가상 메모리와 페이징**을 사용합니다. OS가 DRAM 접근에 필요한 물리 주소 대신 하드웨어 MMU를 통해 매핑되는 가상 주소를 제공하는 일종의 abstraction이라고 볼 수 있습니다. 이런 매핑 정보 역시 메인 메모리에 저장되기 때문에, 메모리 효율성을 위하여 **multi-level paging**이 사용됩니다. x86_64에서는 4 또는 5레벨 페이징을 사용하며, 가상 주소의 각 비트 필드가 해당 레벨 페이지 테이블의 인덱스로 작용합니다. 최상위 페이지 테이블의 주소는 **CR3** 레지스터에 저장되고, 각 엔트리는 다음 레벨 페이지 테이블의 주소를 가리킵니다. 최하위 레벨의 페이지 테이블은 실제 물리 메모리 영역의 주소를 저장합니다.

**Translation Lookaside Buffer:** 멀티 레벨 페이징의 단점 중 하나는 주소 변환을 할 때마다 3~5회의 DRAM 접근을 필요로 한다는 것입니다. 이를 개선하기 위해 각 CPU 코어는 TLB라는 가상주소가 바로 물리주소와 매핑되어 있는 자료구조를 유지합니다. TLB는 MMU가 가상 주소 변환에 성공하면 채워지고, 특정 명령어 실행에 따라 자동으로 엔트리가 교체되거나 비워질 수 있습니다. OS는 이를 통해 **메모리 일관성** 을 유지합니다.

### Address Randomization
ASLR은 모든 운영체제에서 사용하고 있는 방어 기법으로, 부팅 시 커널의 메모리 레이아웃을 랜덤화합니다. 그러나 실제로는 randomization은 힙, 스택, 바이너리 이미지 같은 **프로그램 영역 단위** 로만 발생하고, 운영체제는 프로그램 영역이 특정 주소 범위 내에 보장하기 때문에, 이러한 제한들이 커널의 코드와 데이터가 2MB 경계에 맞춰 매핑된다는 정보와 결합되면 엔트로피가 9비트 정도로 작아집니다. 그럼에도 유의미한 공격을 하기에는 낮은 확률이기 때문에 Meltdown, `double page fault attack`과 같은 마이크로아키텍처 부채널을 활용한 KASLR 우회가 연구 되었습니다. 

### Timing and Prefetch Side-Channels
어떤 연산이 특정 데이터나 입력에 의존할 때, 공격자들은 **timing side-channel** 기법을 이용하여 숨겨진 값을 알아낼 수 있습니다. 예전부터 마이크로아티텍처 구조, 특히 CPU cache를 이용하여 부채널 공격을 구성하는 연구들(ex: Flush+Reload)이 많이 진행되었는데, 이는 데이터 접근 시간을 측정할 때 데이터가 DRAM에 있을 때와 캐시에 있을 때 분명한 시간 차이가 발생하기 때문입니다. Cache보다는 인기가 덜하지만, TLB 역시 hyperthreading 환경에서의 SGX를 대상으로 하는 부채널 공격에 활용되었습니다. 

**Prefetch Attack:** 성능상의 이유로, ISA는 사용자가 **prefetch** 명령어들로 가상 메모리를 미리 캐시할 수 있도록 허용합니다. Prefetch 명령어는 **해당 주소가 매핑되어 있는지 여부** 에 따라 실행 시간이 달라진다는 점에서 사이클 단위로 측정 가능한 side effect를 수반합니다. 또한 유저 컨텍스트에서 커널 주소와 같은 유효하지 않은 주소에 대한 prefetch를 시도해도 어떤 예외를 발생시키는게 아니라 페널티도 없습니다. 이 기법은 **prefetch attack** 이라 불리며 기존 ASLR에 대한 알려진 우회 방법입니다.

## The EntryBleed Attack
### A Security Vulnerability in KPTI
![e1](/assets/img/posts/papers/Entry_1.png) <br>
KPTI는 유저 페이지 테이블과 커널 페이지 테이블을 분리하는 방어 기법으로 Meltdown 공격에 대항하여 소개되었으며, `prefetch attack`에 대해서도 유효하다고 알려져 있었습니다. 위 그림에서 a는 KPTI의 이상적인 흐름이고, b는 KPTI가 실제 구현입니다. 유저 공간에서 실행 중일 때도 인터럽트, 예외, 시스템 콜을 처리하기 위해 커널 진입점 역할을 하는 trampoline execution이 유저 페이지 테이블에 매핑되어 있어야 합니다. 실제로 리눅스 커널 소스 코드를 보면 시스콜 핸들러 `entry_SYSCALL_64`의 주소가 **syscall_init** 함수에서 **LSTAR** 레지스터에 저장되며, 이 주소는 트램폴린 영역에 포함됩니다. LSTAR는 **MSR(Model-Specific Register)** 로서, 시스템 콜 호출 시 점프할 주소를 CPU에게 알려줍니다. KASLR은 커널 영역 전체를 동일한 오프셋으로 이동시키기 때문에 syscall handler의 주소를 알아내면 바로 KASLR을 무력화할 수 있게 됩니다. 

### Attack Strategy
![e2](/assets/img/posts/papers/Entry_2.png) <br>
권한이 없는 일반 사용자가 KASLR을 우회하는 시나리오는 아래와 같습니다.

1. 사용자 공간에서 시스템 콜을 호출하여 syscall handler의 주소를 TLB에 캐시를 합니다.
2. entry_SYSCALL_64의 주소를 추측한 다음 **prefetch** 를 시도합니다. 
3. 커널 이미지의 가상 주소 범위를 기반으로 가능한 모든 가상 주소를 순회하면서 prefetch를 시도하고 시간을 측정합니다. 가장 짧은 지연 시간은, TLB에 이미 그 가상 주소가 올라와 있었음을 의미하고, 그게 바로 syscall handler의 주소입니다.

시간을 잴 때는 `rdtscp` 명령어를 사용할 수 있고, 비순차 실행의 간섭을 줄이려면 `cpuid`, `mfence` 같은 명령어를 활용할 수 있습니다.

### Root Cause Analysis
```c
SYM_CODE_START(entry_SYSCALL_64)
	UNWIND_HINT_ENTRY
	ENDBR

	swapgs
	/* tss.sp2 is scratch space. */
	movq	%rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
	SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp
```
리눅스 커널의 `arch/x86/entry/entry_64.S`에 있는 `entry_SYSCALL_64` 코드를 보면, 트램폴린에서 커널 내부로 진입을 할 때와 커널에서 트램폴린으로 복귀할 때 모두 CR3 레지스터가 유저 페이지 테이블을 가리키고 있는 것을 확인할 수 있습니다. 

```c
/*
 * Switch to kernel cr3 if not already loaded and return current cr3 in
 * \scratch_reg
 */
.macro SWITCH_TO_KERNEL_CR3 scratch_reg:req
	ALTERNATIVE "jmp .Lend_\@", "", X86_FEATURE_PTI
	movl	%cr3, \scratch_reg
	/* Test if we are already on kernel CR3 */
	testl	$PTI_SWITCH_MASK, \scratch_reg
	jz	.Lend_\@
	andl	$(~PTI_SWITCH_MASK), \scratch_reg
	movl	\scratch_reg, %cr3
	/* Return original CR3 in \scratch_reg */
	orl	$PTI_SWITCH_MASK, \scratch_reg
.Lend_\@:
.endm
```
`movl \scratch_reg, %cr3`에서 볼 수 있듯이 CR3 레지스터에 새 값을 쓰면 x86 아키텍처에서 TLB가 자동으로 flush됩니다. KPTI는 이를 활용하여 유저/커널 모드 전환 시 페이지 테이블을 분리합니다. 그러나 커널에서 유저 모드로 복귀하는 과정에서 트램폴린 코드가 실행되면서 **해당 페이지가 다시 TLB에 캐시** 되기 때문에 flush 효과가 무효화됩니다. 게다가 x86 아키텍처에는 **global bit** 라는 기능이 있는데, 특정 페이지의 TLB flush를 피하게 해주는 비트입니다. 트램폴린 페이지 역시 성능을 위해 이 global bit가 설정되어 있어 CR3가 바뀌어도 TLB에서 지워지지 않고, 공격이 더 안정적으로 작동할 수 있도록 도와줍니다.결과적으로 이 취약점은 소프트웨어(entry handler)나 하드웨어(prefetch semantic) 어느 쪽에서도 쉽게 패치하기 어렵습니다.

## Experimental Verification
본 연구에서는 인텔 기반 시스템 중 4세대부터 9세대 아키텍처까지 공격을 테스트하였다. 10세대부터는 Meltdown에 대한 인텔의 built-in 하드웨어 완화 기법이 들어가 KPTI가 사라지고 다시 커널과 유저 공간이 페이지 테이블을 공유하여 이미 prefetch 공격이 통한다는게 알려져 있습니다. 실험은 KPTI와 KASLR이 활성화된 표준 Linux 커널 빌드에서 수행되었으며, `retpoline` 및 최신 인텔 마이크로코드 업데이트가 적용된 배포판도 포함되었습니다. 공격자가 LPE를 시도하는 시나리오를 더 정확하게 재현하기 위해 낮은 권한의 계정을 만들어 공격을 수행하였습니다. 공격을 수행하고 유출된 `entry_SYSCALL_64` 함수의 주소는 **/proc/kallsyms** 와 비교하여 검증하였습니다.

## Results
### Observable Effects of EntryBleed
![e3](/assets/img/posts/papers/Entry_3.png) <br>
각 그래프마다, prefetch 코드는 KASLR 주소 단위마다(0x200000) 1000회씩 실행이 되었고, 탐색 범위는 `0xffffffff80000000-0xffffffffc0000000`로 설정하였습니다. 이 범위는 x86_64에서 KALSR base로 가능한 값의 범위입니다. 결과에서 확인할 수 있듯이 `entry_SYSCALL_64` 지역에서 측정을 했을 때 유의미하게 측정 시간이 짧아진 것을 확인할 수 있습니다. TLB에 이미 매핑이 되어있어 page table walking을 할 필요가 없었기 때문입니다.

### Analysis of Virtualization Behavior
마지막으로, 본 연구에서는 Linux KVM의 Intel VT-x 환경에서 EntryBleed를 분석하였으며, VM 관련 MMU 최적화 기술인 **EPT, VPID, shadow MMU** 와의 관계를 살펴보았습니다. EPT, VPID는 KVM 드라이버를 로드할 때 비활성화 할 수 있으며, EPT가 꺼지면 shadow MMU가 자동으로 활성화 됩니다. Shadow MMU의 경우 호스트가 `GVA->HPA` 매핑을 유지하는 **shadow 페이지 테이블** 을 유지하며, 게스트 페이지 테이블의 변경에 따라 업데이트가 됩니다.

게스트-호스트 스위치가 되어도 side effect가 남는지를 알아보려면 유저랜드 코드에서 강제로 `Unconditional VM exit`을 발생시켜야 합니다. VM exit이 발생하지 않는 한 게스트간 전환이나 게스트-호스트 전환이 없으니, 하드웨어 가속 VM이 TLB 엔트리를 보존하는 것은 당연하기 때문입니다. 이를 위해, syscall 이후 prefetch 측정 함수 이전에 `Unconditional VM exit`을 발생시키는 **cpuid** 명령어를 삽입하였습니다. 아래 그림은 다양한 VM 구성에 따른 EntryBleed 결과를 보여줍니다. <br>
![e4](/assets/img/posts/papers/Entry_4.png) <br>

a를 보면 EPT는 side effect를 유지하는데 도움이 되지 않는 것을 확인할 수 있는데, EPT는 단순히 2단계 페이지 테이블로 작동하고 있다고 생각하면 당연하다고 볼 수 있습니다. TLB에 없는 가상 주소 접근은 게스트 CR3 레지스터를 기반으로 게스트 VA -> 게스트 PA page table walk를 발생시키고, 이어서 **VMCS(Virtual Machine Control Structure)** 의 EPT 베이스 포인터 레지스터를 기반으로 게스트 PA -> 호스트 PA page table walk를 발생시킵니다. EPT는 일반적으로 TLB 상태에 영향을 주지 않으며, 성공적인 page table walk 후에 캐시된 주소 변환을 저장하는 것 외에는 역할이 없습니다. shadow paging도 마찬가지입니다. 

이와 달리 **VPID(Virtual Processor ID)** 는 그래프의 b, c에서 볼 수 있듯이 side effet를 남기는데 중요한 역할을 합니다. VPID는 TLB로 하여금 여러 주소 공간들의 주소 변환을 캐시할 수 있게 해줍니다. CPU는 실행 문맥에 따라 어떤 TLB를 쓸 지 고를 수 있고, 게스트-호스트 컨테스트 스위칭이 발생할 때마다 TLB를 flush하는 걸 피할 수 있습니다. Host TLB는 **별도의 VPID 공간** 에 있기 때문에 VM exit이 호출되더라도 guest TLB는 바로 flush 되지 않습니다. 

신기하게도 VPID없이 shadow paging만 사용하는 환경에서도 미세하게 side effect가 관측이 되지만 자세한 이유를 분석하지는 못하였습니다.

## Mitigation Proposal
한가지 가능한 솔루션은 `kernel exception handler`가 포함된 공간을 exception table과 관련된 MSR 레지스터가 초기화되기 전에 부팅중 재배치를 하는 것이다. Prefetch 공격을 통해 여전히 트램폴린의 offset이 유출될 수 있지만, 커널과 다른 오프셋을 사용하기에 KASLR 무력화로 이어지지 않게 된다. 비슷한 개념이 이미 **FG-KASLR** 에 존재하는데, 모든 커널 함수들이 부팅 중 랜덤한 오프셋에 따라 재배치 됩니다. 다만 원래 구현은 어셈블리 기반 함수를 랜덤화하지 않아 EntryBleed가 여전히 유효하며, 부팅 시간이 약 1초 증가하는 오버헤드가 존재하여 클라우드 환경에서는 큰 부담이 될 수 있습니다. 마지막으로, 하드웨어 Meltdown 완화가 적용된 CPU에서 KPTI를 비활성화하는 것은 권장되지 않습니다. 기존 prefetch 공격이 보여주듯이, 커널과 유저 공간이 페이지 테이블을 공유하는 구조를 악용하는 취약점이 앞으로도 발견될 수 있기 때문입니다. 