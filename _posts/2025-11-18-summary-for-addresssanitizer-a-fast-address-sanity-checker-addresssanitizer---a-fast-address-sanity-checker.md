---
title: "Summary for AddressSanitizer: A Fast Address Sanity Checker"
date: 2025-11-18 01:41:18 +0900
categories: [Papers]
tags: []
---

# Summary for AddressSanitizer: A Fast Address Sanity Checker

# Index
- [1. Introduction](#introduction)
- [2. Related Work](#related-work)
- [3. AddressSanitizer Algorithm](#addresssanitizer-algorithm)
- [4. Evaluation](#evaluation)

# Introduction
많은 메모리 에러 탐지 도구들이 존재하고, 속도, 메모리 소비, 탐지 가능한 버그 유형 등에서 차이가 많이 나나 대부분 overhead가 크거나, 속도가 빠른 대신 탐지력이 떨어진다는 문제가 있다. 우리는 성능과 커버리지를 결합한 새로운 도구인 **AdressSanitizer** 을 제시한다. 상대적으로 낮은 비용인 73 퍼센트의 속도 저하와 3.4배의 메모리 사용량 증가로 `out-of-bounds access`와 해제된 힙 메모리의 사용을 탐지해낸다. 

AddressSanitizer는 두 부분으로 구성된다: **계측 모듈** 과 **런타임 라이브러리** 이다. 계측 모듈은 각 메모리 접근에 대해 **shadow state** 를 확인하도록 코드를 수정하고, 오버플로우와 언더플로우 탐지를 위해 스택과 global objects 주변에 **poisoned redzones** 를 생성한다. 현재 구현은 `LLVM` 컴파일러 인프라를 기반으로 한다.

런타임 라이브러리는 malloc, free 및 관련 함수들을 대체하고 할당된 힙 영역 주변에 레드존을 생성하며 해제된 힙 영역의 재사용을 지연시키면서 에러를 보고한다.

## Contributions
- 메모리 오류 탐지기가 기존보다 훨씬 낮은 오버헤드로 shadow memory를 활용할 수 있음을 보임
- 새로운 shadow state 인코딩을 제시: 128대 1 매핑이라는 컴팩트한 shadow memory 가능하게 함
- 새로운 shadow encoding을 대상으로 하는 특화된 메모리 할당자 설명
- 메모리 버그를 효율적으로 식별하는 도구 평가

# Related Work
이미 존재하는 메모리 탐지 도구와 기술을 알아본다.

## Shadow Memory
많은 다른 도구들이 각 애플리케이션 데이터 조각에 해당하는 메타데이터를 저장하기 위해 **shadow memory** 를 활용한다. 일반적으로 애플리케이션의 주소는 직접적인 스케일과 오프셋을 통해 shadow memory로 매핑되거나, `table lookup`을 포함하는 추가적인 translation 레벨을 통해 매핑된다. 

직접 매핑의 예로 `TaintTrace`와 `LIFT`가 있다. TaintTrace는 애플리케이션 주소 공간과 동일한 크기의 shadow space를 필요로 하는데, 이 경우 정상 주소 공간의 절반만으로는 생존할 수 없는 애플리케이션을 지원하기 어렵다. LIFT의 shadow space 공간 크기는 애플리케이션의 8분의 1이다. 

주소 공간 레이아웃에서 더 많은 유연성을 제공하기 위해 일부 도구들은 **multi-level translation** 방식을 사용한다. Valgrind와 Dr.Memory는 shadow memory를 조각들로 나누고 shadow address를 얻기 위해 table lookup을 사용하여 추가적인 메모리 로드를 필요로 한다. 

Umbra는 레이아웃 유연성과 효율성을 결합하여, 비균일하고 동적으로 조정되는 스케일과 오프셋 방식을 통해 테이블 조회를 피한다. BoundLess는 64비트 포인터의 상위 16비트에 일부 메타데이터를 저장하지만 느린 경로에서는 더 전통적인 shadow memory로 되돌아간다. 

## Instrumentation
많은 메모리 오류 탐지기들이 **binary instrumentation** 을 기반으로 한다. Valgrind, Dr.Memory, BoundsChecker 같은 유명한 도구들은 일반저긍로 거짓 양성 없이 힙 메모리에 대한 범위 초과와 use-after-free 버그를 찾아낸다. 우리가 아는 한 어떤 도구도 스택이나 전역 변수에서의 범위 초과 버그를 찾아내지 못한다. 

Mudflap은 컴파일 타임 계측을 사용하며 이를 통해 스택 객체에 대한 `out-of-bounds access`를 탐지할 수 있다. 그러나 하나의 스택 프레임에서 서로 다른 스택 객체들 사이에 레드존을 삽입하지 않기 때문에 모든 스택 버퍼 오버플로우 버그를 잡아내지는 못한다. 또한 복잡한 C++ 코드의 경우 거짓 양성 보고도 존재한다.

## Debug Allocators
다른 유형의 메모리 에러 탐지기의 경우 특수한 메모리 할당자를 사용하고 나머지 실행은 바꾸지 않는다. 

Electric Fence, Duma, GuardMalloc, Page Heap과 같은 도구 들은 **CPU Page protection** 을 사용한다. 각 할당된 영역은 `전용 페이지(또는 페이지 집합)`에 배치된다. 오른쪽(그리고, 또는 왼쪽)에 하나의 추가 페이지가 할당되고 접근 불가로 표시된다. 이러한 페이지에 접근하는 page fault는 범위 초과 오류로 보고되는데, 이러한 도구들은 굉장히 큰 메모리 오버헤드를 발생시키고 일부 유형의 버그도 놓칠 수 있다. 

DieHarder와 Dmalloc과 같은 일부 malloc 구현들은 확률적, 지연 기반으로 메모리 버그를 찾는다. 수정된 `malloc` 함수는 사용자에게 반환되는 메모리 영역 주변에 **red zone** 을 추가하고, 새로 할당된 영역에 magic value로 채운다. **free** 함수 역시 magic value를 쓴다.Magic value가 읽히면 프로그램이 초기화되지 않았거나 범위 밖의 값을 읽었다는 뜻이지만, 즉각적인 탐지가 없고 탐지 역시 확률적이다. 

Red zone의 magic value가 덮어 씌워지면 나중에 **free** 할 때 레드존이 검사되면서 탐지가 되지만, 문제가 발생한 시점까지는 알아내지 못한다. 동일한 magic value 기법은 버퍼 오버플로우 보호에도 가끔 사용된다. StackGuard와 ProPolice(현재 GCC에서 StackGuard를 다시 구현한 것)는 현재 스택 프레임에서 지역 변수와 반환 주소 사이에 canary 값을 배치하고 이를 통해 **stack smashing** 공격을 방지할 수 있다. 그러나 스택 객체에 대한 임의의 `out-of-bounds access`를 탐지할 수는 없다. 

# AddressSanitizer Algorithm
높은 수준에서는 우리 접근 방식이 Valgrind 기반의 `AddrCheck`와 유사하다. Shadow memory를 사용하여 애플리케이션 메모리의 각 바이트가 접근하기에 안전한지 기록하고 각 애플리케이션 로드나 저장 시 shadow memory를 검사하기 위해 계측을 사용한다. 그러나 우리 도구는 더 효율적인 shadow memory mapping, 더 컴팩트한 인코딩을 사용하고 힙 뿐만 아니라 스택과 전역 변수에서 오류를 탐지하고 속도도 빠르다. 다음 섹션들은 어떻게 shadow memory를 매핑, 인코딩하고 계측을 삽입하는지, 그리고 런타임 라이브러리가 어떻게 작동하는지 설명한다.

## Shadow Memory
**malloc** 함수에 의해 반환되는 메모리 주소들은 보통 8 바이트로 정렬된다. 이는 애플리케이션 힙 메모리의 모든 정렬된 8바이트 시퀀스가 9개의 다른 상태 중 하나에 있다는 결론으로 이어진다: 첫 번째 k(0 <= k <= 8) 바이트는 **addressable** 하고 나머지 8-k 바이트는 그렇지 않다. 이 상태는 shadow memory의 단일 바이트로 인코딩 될 수 있다.

AddressSanitizer는 **가상 주소 공간의 8분의 1** 을 shadow memory에 할당하고, 애플리케이션 주소를 해당하는 shadow address로 변환하기 위해 스케일과 오프셋을 가진 직접 매핑을 사용한다. 에플리케이션 메모리 주소 Addr이 주어지면 shadow byte의 주소는 `(Addr>>3)+Offset`으로 계산된다. `Max-1`이 가상 주소 공간에서 최대 유효 주소라면 Offset의 값은 Offset부터 Offset+Max/8까지의 영역이 시작 시 점유되지 않도록 선택되어야 한다. 

Umbra와 다르게 Offset은 모든 플랫폼에 대해 정적으로 선택되어야 하지만, 우리는 이를 심각한 제한으로 생각하지는 않는다. 가상 주소 공간이 `0x00000000-0xffffffff`인 일반적인 32비트 시스템에서 우리는 `Offset=0x20000000(2^29)`을 사용한다. 47개의 유효 주소 비트를 가진 64비트 시스템에서는 `Offset = 0x0000100000000000 (2^44)`을 사용한다. 일부 경우에는(예를 들어 리눅스에서 -fPIE/-pie 컴파일러 플래그와 함께) 계측을 더욱 단순화하기 위해 0 오프셋을 사용할 수 있다. <br>

![ASAN_mapping](/assets/img/posts/papers/KASAN_1.png) <br>

위 그림은 주소 공간 레이아웃을 보여준다. 애플리케이션 메모리는 해당하는 shadow region에 매핑되는 두 부분(낮은 부분과 높은 부분)으로 나뉜다. Shadow region의 주소에 **shadow mapping** 을 적용하면 페이지 보호를 통해 **접근 불가** 로 표시된 **Bad** 영역의 주소를 얻게 된다.

각 shadow byte에 대해 다음 인코딩을 사용한다: 0은 해당하는 애플리케이션 메모리 영역의 8바이트가 전부 **addressable** 하다는 의미이다. k( 1 <= k <= 7)는 첫 번째 k 바이트가 주소 시정 가능하다는 뜻이다. 모든 음수 값은 8바이트가 전부 주소 지정 불가능하다는 것을 뜻한다. 서로 다른 종류의 지정 불가능한 유형을 구별하기 위해(힙, 스택, 전역, 해제된 메모리) 다른 음수 값들을 사용한다.

이 **shadow mapping** 은 `(Addr>>Scale)+Offset`의 형태로 일반화 될 수 있는데, 이때 scale은 1과 7 사이이다. `Scale=N`일 때 Shadow memory는 가상 주소 공간의 `1/2^N`을 차지하고 레드존의 최소 크기는 `2^N` 바이트이다. 각 **Shadow Byte** 는 2^N 바이트의 상태를 설명하고 `2^N+1`개의 서로 다른 값을 인코딩한다. Scale의 더 큰 값은 더 적은 Shadow Memory를 필요로 하지만 정렬 요구사항을 만족시키기 위해 더 큰 레드존 크기를 요구한다.3보다 더 큰 Scale 값은 8바이트 접근에 대해 더 복잡한 instrumentation을 필요로 하지만 주소 공간의 연속된 8분의 1을 포기할 수 없는 애플리케이션에 대해 더 많은 유연성을 제공한다. 

## Instrumentation
8바이트 메모리 접근을 **instrument(계측)** 할 때, AddressSanitizer는 해당하는 Shadow Byte의 주소를 계산하고 그 바이트를 로드하며 0인지 확인한다.

```
ShadowAddr = (Addr >> 3) + Offset;
if (*ShadowAddr != 0)
    ReportAndCrash(Addr);
```
1바이트, 2바이트, 또는 4바이트 접근을 계측할 때는 계측이 약간 더 복잡하다: Shadow 값이 양수인 경우(즉, 8바이트 워드에서 첫 번째 k바이트만 주소 지정이 가능한 경우) 주소의 마지막 3비트를 k와 비교해야 한다. 

```
ShadowAddr = (Addr >> 3) + Offset;
k = *ShadowAddr;
if (k != 0 && ((Addr & 7) + AccessSize > k))
    ReportAndCrash(Addr);
```

두 경우 모두 계측은 원본 코드의 각 메모리 접근에 대해 단 하나의 메모리 읽기만 삽입한다. 우리는 N바이트 접근이 N에 정렬되어 있다고 가정한다. AddressSanitizer는 정렬되지 않은 접근으로 인한 버그를 놓칠 수 있다. 우리는 AddressSanitizer 계측 패스를 **LLVM 최적화 파이프라인** 의 맨 끝에 배치하여 LLVM 최적화 과정에서 살아남은 메모리 접근만 계측한다. 즉, 최적화로 제거된 스택 객체에 대한 접근은 계측할 필요 없고, LLVM 코드 생성기에 의해 생성된 메모리 접근(**레지스터 스필**)도 필요가 없다.

오류 보고 코드(`ReportAndCrash`)는 최대 한번만 실행되지만, 삽입이 많이 되기 때문에 간단한 함수 호출을 사용했고, 하드뒈어 예외 생성 옵션도 쓸 수 있다. 

## Run-time Library
런타임 라이브러리의 주요 목적은 **Shadow Memory를 관리** 하는 것이다. 애플리케이션이 시작할 때 전체 Shadow Space가 매핑되어 프로그램의 다른 부분이 이를 사용할 수 없도록 한다. Shadow Memory의 Bad 세그먼트는 보호된다. Linux에서는 Shadow Space가 시작 시 항상 비어있어 매핑이 항상 성공한다. MacOS에서는 ASLR을 꺼줘야 하고 동일한 Shadow Memory Layout이 Windows에서도 작동함을 보여준다.

**malloc** 과 **free** 함수들은 특수화된 구현으로 대체된다. malloc은 반환된 영역 주변에 레드존이라는 추가 메모리를 할당한다. 레드존들은 Addressable 하지 않거나 독성화된 것으로 표시된다. 레드존이 클수록 탐지될 오버플로우나 언더플로우도 커진다. 할당자 내부의 메모리 영역들은 객체 크기 범위에 해당하는 프리리스트 배열로 구성된다. 요청된 객체 크기에 해당하는 프리리스트가 비어있을 때, 레드존을 포함한 큰 메모리 영역 그룹이 운영체제로부터 할당된다(예를 들어 mmap 같은 함수를 쓸 때). n개 영역에 대해 우리는 n+1개의 레드존을 할당하여, 한 영역의 오른쪽 레드존이 일반적으로 다른 영역의 왼쪽 레드존이 되도록 한다 <br>

![layout](/assets/img/posts/papers/KASAN_2.png) <br>

왼쪽 레드존은 할당자의 내부 데이터(할당 크기, 스레드 ID 등)을 저장하는 데 사용된다. 따라서 힙 레드존의 최소 크기는 현재 `32바이트`이다. 이 내부 데이터는 버퍼 언더플로우에 의해 손상될 수 없는데, 그러한 언더플로우는 실제 저장 이전에 즉시 탐지되기 때문이다(언더플로우가 계측된 코드에서 발생하는 경우). **free** 함수는 전체 메모리 영역을 독성화하고 이를 격리 상태에 둬서, 이 영역이 malloc에 의해 곧바도 할당되지 않도록 한다. 현재 격리는 언제든지 고정된 양의 메모리를 가지는 **FIFO 큐** 로 구현된다.

기본적으로 malloc과 free는 버그 보고를 하기 위해 현재 콜 스택을 기록한다. malloc 콜 스택은 왼쪽 레드존에 저장되고, free 콜 스택은 메모리 영역 자체의 시작 부분에 저장된다.

## Stack And Globals
전역, 스택 객체에 대한 **out-of-bounds access** 버그를 탐지하기 위해 AddressSanitizer는 그런 객체를 둘러싸는 독성화된 레드존을 생성해야 한다. 전역 객체의 경우 레드존은 컴파일 타임에 생성되고, 레드존의 주소는 애플리케이션이 시작될 때 **runtime library** 로 전달된다. 런타임 라이브러리의 함수는 전달받은 레드존 주소를 독성화하고 향후 보고를 위해 주소를 기록한다. 

스택 객체의 경우 런타임 도중에 레드존이 만들어지고 독성화된다. 현재 32바이트(정렬을 위해 최대 31바이트 추가)의 레드존이 사용된다. 예를 들어 다음과 같은 프로그램이 주어질 때

```
void foo() {
    char a[10];
    <function body>
}
```
다음과 같은 코드가 반환된다.

```
void foo() {
    char rz1[32]
    char arr[10];
    char rz2[32-10+32];
    unsigned *shadow =
        (unsigned*)(((long)rz1>>8)+Offset);
    // poison the redzones around arr.
    shadow[0] = 0xffffffff; // rz1
    shadow[1] = 0xffff0200; // arr and rz2
    shadow[2] = 0xffffffff; // rz2
    <function body>
    // un-poison all.
    shadow[0] = shadow[1] = shadow[2] = 0; }
```

## False Negatives
위의 계측 방식은 아주 드문 유형의 버그를 놓칠 수 있다: 부분적으로 범위를 벗어나는 **정렬되지 않은** 접근. 예를 들어
```
int *a = new int[2]; // 8바이트 정렬
int *u = (int*)((char*)a + 6);
*u = 1; // 범위 [6-9]에 접근
```
현재는 이런 유형의 버그를 무시하고 있다(생각해낸 해결책들이 전부 common path를 느리게 만듦)

다음 두 경우의 버그도 놓칠 수 있다.

1. OOB 접근이 객체로부터 너무 멀리 떨어진 메모리에 접촉하여 우연히 유효한 메모리에 접근할 때
```
char *a = new char[100];
char *b = new char[1000];
a[500] = 0; // b 어딘가에 접근 가능
```
힙 레드존 내의 모든 OOB access는 무조건 탐지가 되니, 메모리 여유가 충분하다면 최대 128바이트의 큰 레드존 사용을 권장한다.

2. **free** 와 그 후의 사용 사이에 많은 양의 메모리가 할당되고 해제되었다면, 해제 후 사용이 탐지되지 않을 수도 있다.
```
char *a = new char[1 << 20]; // 1MB
delete [] a; // <<< "free"
char *b = new char[1 << 28]; // 256MB
delete [] b; // 격리 큐를 비운다.
char *c = new char[1 << 20]; // 1MB
a[0] = 0; // "use". 'c'에 도달할 수 있음.
```

## False Positives
요약하자면, ASAN에는 거짓 양성이 없다. 하지만 개발 과정에서 여러 오류를 해결했어야 했는데, 아래에서 언급한다.

### Conflict With Load Widening
**load widening** 이라 불리는 아주 흔한 컴파일러 최적화 기법이 있는데, ASAN의 계측과 충돌을 일으켰다. 다음 C 코드를 보자
```
struct X {char a, b, c; };
void foo() {
    X x; ...
    ... = x.a + x.c; }
```

`객체 x`가 크기가 3이고 정렬이 최소 4이다. load widening은 x.a+x.c를 하나의 4바이트 로드로 변환하는데, 이는 부분적으로 객체 경계를 넘나든다. 최적화 파이프라인 후반에 ASAN이 이 4바이트 로드를 계측하면 거짓 양성으로 이어지게 되었다. 이를 피하기 위해 ASAN 계측이 활성화 되어 있을 때는 LLVM의 load widening을 부분적으로 비활성화하였다.

### Conflict With Clone
**clone system call** 과 관련된 여러 거짓 보고를 관측할 수 있었다. 먼저 프로세스가 `CLONE_VM|CLONE_FILES` 플래그와 함께 clone을 호출하는데, 이는 부모와 메모리를 공유하는 자식 프로세스를 생성한다. 특히 자식의 스택에서 사용되는 메모리는 여전히 부모에게 속한다. 그런 다음 자식 프로세스가 스택에 객체를 가진 함수를 호출하고, ASAN 계측이 스택 객체 레드존을 독성화한다. 마지막으로 함수를 종료하고 레드존을 비독성화하지 않은 채로 자식 프로세스가 **반환하지 않는 함수(exit, exec)** 을 호출하면 결과적으로 부모 주소 공간의 일부가 독성화된 채로 남게 되어 오류 보고로 이어지게 된다. 이 경우 exit, exec과 같은 반환하지 않는 함수들을 찾아서 호출 전에 전체 스택 메모리를 비독성화하는 방법으로 해결했다.

### Internal Wild Dereferences
함수가 의도적으로 미지의 메모리를 읽는 여러 사례를 보았는데, 예를 들어 저수준 코드가 스택의 두 주소 사이를 반복하면서 여러 스택 프레임 사이를 가로지르는 경우가 있었다. 이러한 경우들을 위해 C/C++ 함수 선언에 추가되어야 하는 **no_address_safety_analysis** 속성을 구현하였다.

## Threads
ASAN은 **thread-safe** 하다. Shadow Memory는 해당하는 애플리케이션 메모리가 접근 불가능할 때만 수정된다(malloc이나 free 내부, 스택 프레임의 생성이나 소멸, 모듈 초기화 중에). Shadow Memory에 대한 다른 모든 접근은 읽기이다. malloc과 free 함수들은 모든 호출에서 잠금을 피하기 위해 **thread-local cache** 를 사용한다(대부분의 현대적 malloc처럼). 원본 프로그램이 메모리 접근과 해당 메모리의 삭제 사이에 race를 갖고 있다면, ASAN은 때때로 이를 UAF로 탐지할 수 있지만 보장은 안된다. Thread ID는 모든 malloc과 free에 대해 기록되고, 스레드 생성 콜 스택과 함께 오류 메시지에 보고된다. 

# Evaluation
우리는 SPEC CPU2006과 C/C++ 벤치마크에서 ASAN의 성능을 측정했다. 계측된 바이너리의 성능을 일반적인 LLVM 컴파일러(`clang -O2`)를 사용하여 빌드된 바이너리와 비교했다. 32 바이트 레드존을 사용하고, malloc과 free 중 스택 언와인딩을 비활성화 했으며 격리 크기를 0으로 설정하였다. <br>

![slowdown](/assets/img/posts/papers/KASAN_3.png) <br>

위 그림은 CPU2006에서 평균 속도 저하가 73%임을 보여준다. 또한 쓰기만 계측될 때의 ASAN 성능을 측정하였는데, 평균 저하가 26%였다. 이 모드는 성능이 중요한 환경에서 메모리 버그의 부분집합을 탐지할 때 사용할 수 있다. 

또한 서로 다른 매핑 **Scale** 과 **Offset** 값들의 성능도 평가하였다. Scale 값이 3보다 클 경우 평균적으로 약간 더 느린 코드를 생성하고 Scale=4,5 메모리 사용량은 3일때와 비슷하다. 값이 6,7인 경우 더 큰 레드존이 필요하기에 메모리 사용량이 증가한다. Offset을 0으로 설정하면 (-fPIE/-pie 필요) 약간의 속도 향상이 가능했다. <br>

![table1](/assets/img/posts/papers/KASAN_4.png) <br>

위 테이블은 메모리 사용량 증가 정도를 보여준다. 대부분의 오버헤드는 **malloc red zone** 에서 오고 평균적인 증가율은 3.37x 였다. <br>

![table2](/assets/img/posts/papers/KASAN_5.png) <br>

그리고 이 테이블은 스택 크기 증가량을 요약한 것이다. 6개의 벤치마크 정도가 유의미한 스택 크기 변화를 보였고, 3개의 벤치마크만이 10% 이상의 증가를 보였다. 

## Comparison
ASAN을 다른 도구들과 비교하는 것은 까다로운데, 다른 도구들은 서로 다른 종류의 버그를 찾기 때문이다. Valgrind와 Dr.Memory는 CPU2006에서 각각 20배, 10배의 속도 저하를 발생시키나 다른 종류의 버그를 탐지한다. 그나마 ASAN과 제일 비슷한 Mudflap은 속도 저하가 2배에서 41배까지 다양하며 여러 벤치마크에서 메모리 부족 오류로 실패한다. 

**CPU guard page**를 사용하는 디버그 malloc 구현들은 일반적으로 malloc 집약적인 애플리케이션에서만 속도를 저하시킨다. 리눅스용 무료 guard page 구현인 **Duma**에서는 벤치마크 18개 중 12개가 메모리 부족 오류로 크래시 되었다. 

## AddressSanitizer Deployment
`Chromiun` 오픈소스 브라우저는 2011년 5월부터 10개월간 테스트를 하였고, 300개가 넘는 버그를 탐지했다. 버그 리포트의 두 가지 주요 원천은 기존의 **unit test** 와 **targeted random test generation, fuzzing** 이었다. Chromium 외에도 많은 양의 다른 코드를 테스트하여 많은 버그를 발견하였고, `heap-use-after-free`가 제일 빈번했지만, 다른 유형도 많았다.
