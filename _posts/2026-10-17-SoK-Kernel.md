---
title: "SoK: Take a Deep Step into Linux Kernel Hardening Effectiveness from the Offensive-Defensive Perspective"
date: 2026-10-17 00:00:00 +0900
categories: [Papers]
tags: [security, linux, kernel]
permalink: /posts/SoK-Kernel-Hardening/
math: true
---

# SoK: Take a Deep Step into Linux Kernel Hardening Effectiveness from the Offensive-Defensive Perspective
## Introduction
리눅스 커널은 하루에도 수많은 패치를 받으며 개발이 활발하게 이뤄지고 있으며 슈퍼컴퓨터와 수많은 서버들의 기반이 되고 있습니다. 이 때문에 리눅스 커널은 매력적인 공격 대상이 되곤 하는데, 공격자들은 커널 내부 에러를 메모리 오염으로 발전시켜 **exploitation primitive** 를 구축하고 권한 상승을 얻는 것을 목표로 합니다. 이에 대응하기 위해 리눅스 커널은 여러 **kernel hardening mechanism** 을 만들어내고 있습니다. 

본 논문은 공격자 관점에서 커널 익스플로잇 과정(메모리 오염, 프리미티브 획득, 목표 달성)을 살펴보고, 각 단계에서 사용되는 공격 벡터와 경로를 분석합니다. 이어 커널 보호 기법을 체계적으로 분류하여 각 기법의 방어 범위와 약점, 다른 기법과의 상호작용을 평가합니다. 연구진은 102개의 취약점에 대한 121개의 공개 익스플로잇을 분석하여 64개의 공격 벡터와 51개의 방어 기법을 정리했습니다. 그 결과 23개의 공격 벡터에는 대응하는 방어 기법이 없었고, 8개의 공격 경로는 20개가 넘는 익스플로잇에서 반복적으로 나타났습니다. 또한 방어 기법 중 20개는 비교적 안전했지만, 31개는 우회 가능하거나 더 이상 유효하지 않은 것으로 평가했습니다.

## Attack Decomposition Framework
![s1](/assets/img/posts/papers/sok_kernel_hardening_1.png) <br>

위 그림은 attack decomposition framework의 요약을 나타낸 모습입니다. 커널 익스플로잇의 각 단계에는 공격 벡터들이 라벨링 되어 있고, 이러한 벡터들은 `Fully Blocked Vector`, `Partially Blocked Vector`, `Unmitigated Vector` 세 종류로 분류가 됩니다. <br>

![s2](/assets/img/posts/papers/sok_kernel_hardening_2.png) <br>

위 그림은 이전의 요약을 확장하여 각 단계의 공격 벡터와 커널 보호 기법을 보여줍니다. 둥근 모서리의 직사각형에 있는 `@3`은 [Figure 4](#fig4)에 정리된 세 번째 공격 벡터를, `#2`는 두 번째 방어 기법을 의미합니다. 완전히 차단된 공격 벡터는 식별자만 표시합니다. **X/Y**는 해당 벡터를 사용한 Y개의 익스플로잇 중 X개가 방어 기법을 우회했다는 의미입니다. <br>

![s3](/assets/img/posts/papers/sok_kernel_hardening_3.png) <br>

위 그림은 실제 익스플로잇이 프레임워크에 어떻게 매핑되는지를 보여줍니다. 먼저 Phase I에서는 커널 내부 오류(vector @5)가 힙 오버플로우를 일으켜 인접 객체의 메모리를 손상시킵니다.

Phase II에서는 오버플로우와 힙 스프레이(@19)를 결합해 `msg_msg` 이중 연결 리스트의 포인터를 손상시킵니다(@29). 이로 인해 **두 `msg_msg` 객체가 동일한 victim `msg_msg`를 참조**하게 되고, victim을 해제하면 UAF가 발생합니다. 공격자는 해제된 elastic `msg_msg`의 공간을 `sk_buff` 객체로 다시 채운 뒤 길이와 기타 중요 필드를 덮어써 out-of-bounds read를 일으키고 힙 주소를 유출합니다. 유출한 주소로 손상된 리스트 포인터를 조작하여 리스트 무결성을 검사하는 `DEBUG_LIST(#6)`를 우회합니다.

이어 `pipe_buffer`와 `sk_buff`를 이용한 spray-and-read로 함수 포인터와 커널 주소를 유출하여 `KASLR(#38)`을 우회합니다. 이후 함수 포인터를 덮어써 IP 제어 프리미티브를 획득하고, Phase III에서 스택 피벗과 ROP를 수행해 커널 제어 흐름을 탈취함으로써 권한 상승과 컨테이너 탈출을 달성합니다.

### Internal Error To Corruption
<a id="fig4"></a>
![s4](/assets/img/posts/papers/sok_kernel_hardening_4.png) <br>
익스플로잇의 첫 단계는 커널 내부 오류를 유발하여 커널 스택, 힙, 전역/정적 영역에 메모리 오염을 일으키는 것입니다.

#### Error 1: Unlimited Variable-Length Array
C99 표준에서 도입된 `VLA(Variable-Length Array)`는 실행 시점에 크기가 결정되는 가변 길이 배열로, 커널 스택에 할당되며 함수 반환 시 자동으로 해제됩니다. 하지만 커널 스택의 크기는 제한적이기 때문에(x86: 8KB, x64: 16KB), VLA의 길이를 적절히 검증하지 않으면 스택 오버플로우가 발생하여 커널 스택 아래의 메모리 영역이 손상될 수 있습니다.

이를 방어하기 위한 `PAX_MEMORY_STACKLEAK(#1)`은 스택 할당 크기를 검사하여 오버플로우를 방지합니다. 연구진이 분석한 공개 익스플로잇에서는 우회 사례가 발견되지 않아 보수적으로 **효과적인 hardening으로 평가**했습니다. 다만 Linux v4.20에서 VLA가 제거되면서 upstream 커널에는 도입되지 않았습니다.

#### Error 2: Unsanitized Recursive Function Call
검사되지 않는 재귀 함수에서도 스택 오버플로우가 발생할 수 있습니다. 이 경우 커널 스택이 고갈되면 VLA 없이도 스택 오염이 발생하며, 이러한 에러를 막기 위한 hardening은 따로 존재하지 않습니다. 

#### Error 3: Integer Underflow/Overflow
정수 오버플로우/언더플로우는 타입 캐스팅이나 불충분한 경계 검사 등으로 인해 발생합니다. 이 값이 인덱스로 사용되면 out-of-bounds 접근이 발생할 수 있습니다. 이를 막기 위한 `PAX_SIZE_OVERFLOW(#2)`가 있지만, 분석된 4개의 익스플로잇 모두에서 우회되었습니다.

#### Error 4: Incorrect Buffer Index
오버플로우나 언더플로우 없이도 인덱스가 잘못 계산되거나 사용자 공간에서 악의적인 값이 전달될 수 있습니다. 이를 적절히 검증하지 않으면 out-of-bounds 접근이 발생할 수 있습니다(@4, @5). `FORTIFY_SOURCE(#3)`는 `memcpy`, `strcpy`와 같은 메모리 연산의 버퍼 오버플로우를 부분적으로 검사하지만, 잘못된 인덱스를 직접 사용하는 경우에는 이를 탐지하지 못합니다(CVE-2017-18344). 정적인 경계 없이 런타임에 크기가 결정되는 버퍼에는 강력한 방어 수단이 없습니다. 관련 익스플로잇 수는 본문에는 12개, Table I과 Figure 2에는 17개로 서로 다르게 기재되어 있습니다.

#### Error 5: Failing to Check a String is NULL-terminated
C 문자열은 NUL 종료 문자(`\0`)로 끝나야 하지만, 이를 검증하지 않으면 의도된 버퍼 범위를 넘어 읽을 수 있습니다. 이 과정에서 문자열 길이가 잘못 계산되면 힙 오버플로우와 같은 메모리 손상이 발생할 수 있습니다(CVE-2022-0185). 연구진은 이를 직접 방어하는 hardening을 발견하지 못했습니다.

#### Error 6: Type Confusion
커널은 기능 확장을 위해 객체 지향적인 설계를 사용합니다. 예를 들어 `struct tcp6_sock`은 내부 필드로 `struct tcp_sock`을 포함하므로 두 타입의 구조가 유사합니다. Type confusion은 type A 객체를 type B처럼 잘못 다룰 때 발생합니다. 이로 인해 객체가 잘못된 캐시로 반환되면 allocator metadata가 손상되고 UAF로 이어질 수 있습니다. 아래 그림은 그 예시입니다. <br>

![s5](/assets/img/posts/papers/sok_kernel_hardening_5.png) <br>

커널은 `SLAB_FREELIST_HARDENED(#4)`에 cache membership validation을 구현하여 일부 오류를 방어합니다. Table I에서 잘못된 캐시로 객체를 반환해 freelist를 손상하는 `@7`은 차단했지만, 할당된 객체와 재사용 객체가 불일치하는 `@8`은 분석된 2개의 익스플로잇 모두에서 우회되었습니다.

#### Error 7: Failing to Nullify All Pointers When the Referenced Object is Freed
커널이 객체를 할당하면 여러 참조가 생길 수 있습니다. 객체를 해제한 뒤 한 참조만 null 처리하고 나머지 참조를 그대로 두면 **dangling pointer**가 발생하며, 이를 역참조하면 UAF로 이어집니다. 연구진은 이를 막는 커널 방어 기법을 발견하지 못했습니다.

#### Error 8: Reference Miscounting
커널은 객체의 생애주기를 관리할 때 **reference counter**에 의존합니다. 카운터의 증감이 올바르게 구현되지 않으면 값이 너무 일찍 0이 되어 아직 사용 중인 객체가 해제될 수 있습니다. PaX/Grsecurity의 `PAX_REFCOUNT`를 기반으로 upstream Linux v4.13부터 `REFCOUNT_FULL(#5)`이 도입되었습니다. 그러나 이 기법은 증감 연산이 서로 대응한다는 전제에 의존하므로 누락된 increment 등을 탐지하지 못하며, Table I에서는 12개의 익스플로잇 중 9개가 이를 우회했습니다.

#### Error 9: Race Over Pointers
리눅스 커널은 멀티스레드 시스템이므로 포인터에 대한 레이스가 발생할 수 있습니다. 예를 들어 한 스레드가 객체를 해제하는 동시에 다른 스레드가 해당 객체를 역참조하면 UAF가 발생할 수 있습니다. 연구진은 이를 직접 방지하는 방어 기법을 발견하지 못했습니다. 관련 익스플로잇 수는 본문에는 9개, Table I과 Figure 2에는 14개로 서로 다르게 기재되어 있습니다.

#### Error 10: Incorrect Operation On Linked List
![s6](/assets/img/posts/papers/sok_kernel_hardening_6.png) <br>

리눅스 커널은 이중·단일 연결 리스트를 관리하는 표준 API를 제공하지만 구조적 무결성 검사를 강제하지는 않습니다. 따라서 **객체를 리스트에 두 번 삽입하거나, 리스트에서 제거하지 않은 채 해제하면** dangling pointer가 발생할 수 있습니다. 위 그림처럼 해제된 객체가 리스트에 남으면 list head의 `next` 포인터가 dangling pointer를 가리키게 됩니다. 표준 이중 연결 리스트에 해당하는 `@12`는 `DEBUG_LIST(#6)`와 `LIST_HARDENED(#7)`가 부분적으로 방어하지만, 8개의 익스플로잇 중 5개가 이를 우회했습니다. 기타 연결 리스트를 손상시키는 `@13`에는 대응하는 방어 기법이 없습니다.

### Corruption To Primitive
![s7](/assets/img/posts/papers/sok_kernel_hardening_7.png) <br>

#### Stack Corruption
![s8](/assets/img/posts/papers/sok_kernel_hardening_8.png) <br>
스택 손상은 두 가지 경우가 있는데(Stack Depth Overflow, Stack-Based Buffer Overflow) 공격자는 이 두 방법을 통해 리턴 주소를 덮어씁니다. Stack-based buffer overflow에서는 버퍼 너머에 리턴 주소가 있어 직관적으로 덮을 수 있고, Stack depth overflow는 두 가지 접근을 보통 사용합니다. 

**1) Cross-Process Kstack Overwrite:** 커널 v4.9 전에는 kstack이 directly mapped page에서 할당이 되었기 때문에 공격자는 두 스레드를 만들고 두 kstack을 연속되게 만든 다음 한 스레드레서 다른 스레드 kstack의 리턴 주소를 덮는 방식으로 IP control을 획득할 수 있었습니다. 

**2) Pipe-Based Overwrite:** kstack 바로 아래에 pipe page를 할당하여, pipe page에 쓰기 작업을 하는 것으로 리턴 주소를 덮어쓸 수 있습니다. 

#### Heap Corruption
힙 손상으로부터 primitive를 얻을 때 공격자는 보통 힙 조작을 통해 오염 범위 안에 critical variable을 배치하고, 이걸 덮어씌우는 방식을 사용합니다.

