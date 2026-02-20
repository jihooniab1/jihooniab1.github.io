---
title: "Spectre Attacks: Exploiting Speculative Execution"
date: 2026-02-05 00:00:00 +0900
categories: [Papers]
tags: [security, side channel]
permalink: /posts/Spectre-Attacks/
math: true
---

# Summary for Spectre Attacks: Exploiting Speculative Execution

## Introduction
프로세서의 속도가 빨라짐에 따라 이를 활용하고자 하는 여러 마이크로아키텍처 설계 기법들이 등장해왔습니다. 하나는 퍼포먼스 향상을 위해 사용되는 **투기 실행(speculative execution)** 으로, CPU가 앞으로 실행될 실행 경로를 예측하게 하여 미리 실행하게 합니다. 예를 들어 프로그램의 분기가 외부 물리 장치에 의존하여 값을 가져오는데 시간이 굉장히 오래 걸린다고 하면, 이를 기다리는 대신 CPU는 **제어 흐름의 방향을 예측** 하고, 레지스터 상태를 체크포인트로 저장한 뒤 예측된 경로로 실행을 계속합니다. 만약 추측이 틀렸다면, CPU는 저장해둔 상태로 다시 돌아가고, 맞았다면 미리 실행한 결과를 commit 하여 성능 이점을 얻을 수 있게 됩니다. 보안 관점에서, 투기적 실행은 잘못된 방식으로 프로그램을 실행할 수 있다는 것을 의미합니다. 그러나 CPU가 잘못된 투기적 실행 결과를 이전 상태로 되돌려 기능적 정확성을 유지하도록 설계되어 있기 때문에, 이러한 오류는 이전까지 안전하다고 여겨져 왔습니다.

### A. Our Results
본 연구에서는 부정확한 투기 실행을 분석하여 **Spectre attack** 이라는 클래스의 마이크로아키텍처 공격을 제시합니다. 스펙터 공격은 프로세서를 속여 원래는 실행되어서는 안되는 instruction들을 실행하게 합니다. 이렇게 실행된 후 결과가 롤백 되어 architectural effect가 사라지는 instruction들을 **일시적 명령어(transient instruction)** 이라고 합니다. 어떤 일시적 명령어들이 투기 실행될지 영향을 줌으로써 victim의 메모리 공간에서 정보를 유출할 수 있습니다.

본 연구에서는 일시적 명령어 시퀀스를 이용하여 정보를 유출하는 방식으로 스펙터 공격의 가능성을 실증하였으며, 이는 권한 없는 네이티브 코드 뿐만 아니라 portable JavaScript code에서도 가능했습니다.

Native Code: PoC를 위해 메모리 공간 안에 비밀 값을 넣어둔 간단한 victim 프로그램을 만들었습니다. 그 다음, 컴파일된 피해자 바이너리와 운영체제의 공유 라이브러리에서 정보 유출에 악용될 수 있는 명령어 시퀀스를 찾아, CPU의 투기 실행을 통해 이 시퀀스를 일시적 명령어로 실행하는 공격자 프로그램을 작성하였고, victim 주소 공간의 메모리를 읽어낼 수 있었습니다.

JavaScript, eBPF: 프로세스 격리 뿐만 아니라 스펙터 공격은 샌드박싱을 벗어날 때도 사용될 수 있습니다. 본 연구에서는 portable JavaScript code를 통해 브라우저 프로세스의 주소 공간으로부터 데이터를 읽어내는데 성공하였습니다. 추가로 리눅스의 eBPF interpreter와 JIT를 활용하는 공격도 소개합니다.

### B. Our Techniques
스펙터 공격은 i)투기 실행과 ii)microarchitectural covert channel을 통한 데이터 탈취를 조합하여 메모리 격리를 무력화합니다. 공격자는 victim의 메모리나 레지스터를 읽어 covert channel의 송신부 역할을 할 수 있는 명령어 시퀀스를 찾거나 프로세스 주소 공간 내에 배치시킨 다음, CPU가 투기적으로 이 시퀀스를 잘못 실행하게 하여 covert channel을 통해 정보를 추출합니다. 잘못 실행된 명령어들의 실행 결과는 롤백되지만, microarchitectural state는 여전히 남아있게 됩니다. 

위는 스펙터 공격을 간단하게 설명한 것으로, 잘못된 투기 시행을 유도하는 방식에 따라 구체적으로 분류될 수 있습니다. 

#### Variant 1: Exploiting Conditional Branches
스펙터 V1에서 공격자는 CPU의 **branch predictor** 를 틀리게 훈련시켜 분기를 잘못 예측하게 하여, CPU가 원래라면 실행 되지 않았을 코드를 실행하게 하여 프로그램 semantic을 위배하게 합니다. 

```c
if (x < array1_size)
    y = array2[array1[x] * 4096];
```

위 코드에서 변수 x는 `공격자가 제어`하는 데이터입니다. 먼저 mistraining 단계에서 공격자는 **유효한 입력으로 위 코드를 계속 호출** 합니다. 이를 통해 predictor는 다음 if도 true라고 예상하게 됩니다. 그 다음 `array`의 범위 밖에 있는 x를 입력으로 주면, CPU는 조건문 계산을 기다리지 않고, 경계 검사를 만족할 것이라고 추측하며 `array2[array1[x]*4096]`을 계산하는 **명령어를 투기적으로 실행** 합니다. 이때 array2에서 읽는 동작은 악의적인 x를 사용한 array1[x] 값에 따라 결정되는 주소의 데이터를 캐시에 로드합니다. 그리고 하드웨어 프리페칭을 방지하고, 각 값이 서로 다른 캐시 라인에 매핑되도록 4096을 곱합니다. 조건문이 false를 반환하면 CPU는 잘못된 투기 실행을 감지하고 롤백하지만, array2에서의 투기적 읽기는 캐시에 영향을 주기에 공격자는 이를 측정하여 값을 알아낼 수 있습니다.

#### Variant 2: Exploiting Indirect Branches
V2에서 공격자는 victim의 주소 공간에서 gadget을 선택하고, victim이 이를 투기적으로 실행하도록 유도합니다. 소프트웨어 취약점을 이용하는 대신, **Branch Target Buffer(BTB)** 를 훈련시켜 간접 분기가 원래 목적지 대신 가젯 주소로 점프하도록 잘못 예측하게 합니다. BTB는 가상 주소 기반으로 동작하므로, 공격자는 자신의 주소 공간에서 **피해자의 가젯과 같은 가상 주소** 로 간접 분기를 반복 실행하여 훈련시킬 수 있습니다. 가젯이 투기적으로 실행되면 캐시 상태에 흔적이 남고, 이를 사이드 채널로 측정하여 비밀 정보를 추출합니다.

### D. Meltdown
Meltdown은 비순차 실행을 악용하여 커널 메모리를 유출하는 마이크로아키텍처 공격으로 스펙터 공격과는 두 가지 큰 차이가 있습니다.

첫 번째로 스펙터와 다르게 Meltdown은 분기 예측 대신, 명령어가 trap을 발생시킬 때 뒤의 명령어들은 비순차적으로 실행된다는 점을 이용합니다. 두 번째로 Meltdown은 많은 Intel 및 일부 ARM 프로세서에 있는 특정한 취약점을 악용하는데, 이 취약점은 특정 투기적 실행 명령어들이 메모리 보호를 우회할 수 있게 합니다. 이 접근은 trap을 발생시키지만, trap이 발생하기 전에 뒤의 명령어들이 캐시 부채널을 통해 정보를 유출합니다. 

이에 비해 스펙터는 훨씬 넓은 범위의 프로세서에 대해 동작하며 KAISER 기법으로도 공격을 방어할 수 없습니다.

## Background
### Out-of-order Execution
비순차 실행은 프로그램 순서상 **뒤에 있는 명령어들이 앞선 명령어들과 병렬로, 혹은 먼저 실행** 될 수 있도록 하여 프로세서 활용도를 높이는 기법입니다. 최신 프로세서들은 내부적으로 micro-op을 사용하며, 명령어들은 micro-op으로 디코딩되어 실행됩니다. 명령어를 구성하는 모든 micro-op이 완료되면 해당 명령어는 retire되어 레지스터와 architectural state에 결과가 반영됩니다. 이때 retire는 프로그램 순서대로 이루어져 architectural state의 일관성을 유지합니다.

### Speculative Execution
프로세서가 조건 분기에 도달했는데 분기 결과가 아직 확정되지 않은 경우, 프로세서는 현재 레지스터 상태를 저장한 뒤 **프로그램이 진행할 방향을 예측하여 투기적으로 실행** 합니다. 예측이 맞으면 투기 실행 결과가 commit되고, 틀리면 레지스터 상태를 되돌리고 투기 실행 결과를 폐기합니다. Architectural state는 올바르게 복원되지만, 잘못된 예측으로 실행된 명령어들(transient instructions)이 microarchitectural state에 흔적을 남기게 됩니다.

### Branch Prediction
투기 실행 도중 프로세서는 분기 결과를 추측하며 진행하고, Intel 프로세서의 경우 branch predictor가 직접/간접 분기를 위한 여러 예측 메커니즘을 갖고 있습니다.

간접 분기 명령어는 런타임에 계산된 임의의 타겟 주소로 점프할 수 있습니다. x86의 경우 레지스터, 메모리 주소, 또는 스택에 있는 주소로 점프할 수 있으며(`jmp eax`, `jmp [eax]`, `ret`), ARM, MIPS, RISC-V도 간접 분기를 지원합니다.

**Branch Target Buffer(BTB)** 는 최근에 실행된 분기 명령어의 주소와 목적지 주소의 매핑을 유지하며, 프로세서는 BTB를 활용해 명령어를 디코딩하기도 전에 목적지를 예측할 수 있습니다. 조건 분기의 경우 보통 목적지가 명령어에 인코딩 되어 있기 때문에, 프로세서는 최근 branch outcome, taken/not taken 여부를 유지하여 예측에 활용합니다. `return` 명령어도 하나의 간접 분기라고 볼 수 있지만 보통 현대 CPU들은 return 명령어의 목적지를 예측할 때는 별개의 메커니즘을 활용합니다. **Return Stack Buffer(RSB)** 는 최근 call stack의 복사본을 유지합니다. 

BTB, RSB 같은 분기 예측은 주로 물리 코어 간에는 공유되지 않기 때문에, 같은 코어에서 실행된 분기로부터만 학습이 됩니다.

### The Memory Hierarchy
프로세서와 메모리 사이의 속도 차이를 줄이기 위해 프로세서는 여러 레벨로 구성된 캐시를 사용합니다. 캐시는 메모리를 **캐시 라인(cache line)** 이라는 고정 크기 단위(보통 64바이트)로 나누어 관리합니다. 프로세서가 데이터가 필요할 때 먼저 L1 캐시를 확인하고, 없으면 다음 레벨을 거쳐 external memory까지 탐색합니다. 읽기가 완료되면 데이터는 캐시에 저장됩니다. 최신 Intel 프로세서는 보통 3레벨 캐시를 가지며, L1과 L2는 각 코어 전용이고 L3(LLC)는 모든 코어가 공유합니다.

프로세서는 **MESI 프로토콜** 기반의 **cache coherence protocol** 을 사용하여 각 코어의 L1, L2 캐시 일관성을 유지합니다. 한 코어에서 메모리 쓰기가 발생하면, 다른 코어의 캐시에 있는 동일 데이터 복사본은 무효화(invalid) 표시됩니다. 이 현상이 특정 메모리 위치에 반복되면 **cache-line bouncing** 이라 하고, 서로 다른 코어가 주소는 다르지만 같은 캐시 라인에 매핑되는 위치에 접근하면 **false sharing** 이 발생합니다. 이러한 특성은 캐시 사이드 채널 공격에 악용될 수 있습니다.

### Microarchitectural Side-Channel Attacks
여러 프로그램이 같은 하드웨어에서 동시에 실행되면서, 한 프로그램이 마이크로아키텍처 상태를 바꾸면 다른 프로그램이 이에 영향을 받을 수 있고 이는 의도치 않은 정보 유출로 이어질 수 있습니다. 초기 마이크로아키텍처 부채널 공격들은 타이밍 차이와 L1 데이터 캐시를 이용해 정보를 유출하였고, 시간이 지남에 따라 부채널들이 확장되어 instruction cache, 낮은 레벨의 캐시들, BTB, branch history를 활용한 연구들도 있었습니다. 

본 연구에서는 Flush+Reload와 Evict+Reload를 이용하여 민감한 정보를 유출합니다. 두 기법의 차이는 캐시 라인을 축출하는 방법입니다. **Flush+Reload** 는 `clflush` 명령어로 직접 축출하고, **Evict+Reload** 는 같은 캐시 셋에 매핑되는 다른 주소들에 접근하여 경쟁을 유발해 축출합니다.

## Attack Overview
스펙터 공격은 대부분 setup phase로 시작합니다. 공격자는 프로세서를 mistrain하고, 투기적 실행을 유도하기 위해 분기 조건이나 간접 분기 목적지 등의 데이터를 캐시에서 축출합니다. 또한 정보 유출에 사용할 covert channel을 준비합니다. Second phase에서 프로세서가 투기적으로 명령어를 실행하여 민감한 정보를 covert channel로 전송합니다. 공격자는 시스템 콜, 소켓, 파일 등을 통해 victim의 투기적 실행을 트리거할 수 있습니다. 또는 공격자가 자신의 코드의 잘못된 투기적 실행을 활용하여 같은 프로세스 내에서 민감한 정보를 얻을 수도 있습니다. 예를 들어 인터프리터, JIT 컴파일러, 안전한 언어 등에 의해 샌드박싱된 공격 코드가 투기적 실행을 통해 원래는 접근할 수 없는 메모리를 읽어낼 수 있습니다. Final phase에서 공격자는 Flush+Reload 등의 기법으로 covert channel에서 민감한 정보를 복원합니다.

스펙터 공격은 투기적 실행이 victim이 정상적으로 접근 가능한(페이지 폴트 등의 예외를 일으키지 않는) 메모리만 읽을 수 있다고 가정합니다. 따라서 유저 명령어의 비순차 실행을 통해 커널 메모리를 직접 읽는 Meltdown과는 차이가 있으며, 프로세서가 유저 프로세스의 투기적 실행에서 커널 메모리 접근을 막더라도 스펙터 공격은 여전히 작동합니다.

## Variant 1: Exploiting Conditional Branch Misprediction
```c
if (x < array1_size)
    y = array2[array1[x] * 4096];
```
![s1](/assets/img/posts/papers/spectre_1.png) <br>

위 그림은 경계 검사가 완료되기 전에 프로세서가 투기적 실행을 할 때, 경계 검사와 투기적 실행이 결합되었을 때의 네가지 경우를 보여줍니다. 

`변수 x`의 값이 array1을 벗어나 비밀값 k의 위치를 가리키도록 악의적으로 주어졌고 array1_size와 array2는 캐시 되어 있지 않고 k만 캐시가 되어있으며 이전 연산들을 통해 branch predictor가 이번 조건 분기도 참일 것이라고 예측한 상황이라고 합시다.

코드가 실행되면, x와 array1_size를 비교할 때, array1_size는 DRAM에 있어 값을 가져오는데 시간이 오래 걸리고 branch predictor는 if가 true를 반환하다고 예측을 합니다. 투기적 실행은 x값을 기준으로 메모리를 계산하고, 캐시되어 있는 비밀값 k를 빠르게 반환합니다. 그 후 `array2[k * 4096]`의 주소를 계산하여, 이 주소에 대한 읽기 요청을 보내게 되는데, 경계 검사가 실패하여 투기 실행이 롤백되더라도 array2에 대한 투기적 읽기는 캐시에 영향을 주게 됩니다. 이후 공격자는 Flush+Reload, Prime+Probe 등을 통해 캐시 상태를 관측하고 k 값을 알아낼 수 있게 됩니다. 만약 물리 페이지를 공유하지 않거나 다른 이유로 Flush+Reload를 못 쓰면 Evict+Time 방법을 쓸 수도 있습니다. 공격자가 array1 배열의 내용을 알고 있는 상태에서, 비밀값 k를 읽은 직후 **array1[x'] = k** 를 만족할 것으로 예상되는 `x'`을 골라서 다시 코드를 실행했을 때 추측이 맞았다면 array2 접근이 빠르게 이뤄질 것입니다.

### Experimental Results
스펙터 공격은 Intel, AMD, ARM 등 거의 모든 아키텍처의 프로세서에서 작동하였고, 또한 투기적 실행이 꽤 길게 진행된다는 사실도 발견하였습니다. if문과 array 접근 사이에 188개 명령어를 넣어도 공격이 동작하는 것을 확인하였습니다. 

### Example Implementation in C
[Spectre_poc](https://github.com/jihooniab1/jihooniab1.github.io/blob/main/code/paper/spectre_poc.c)에 있는 코드는 x86 프로세서에서의 PoC C 코드입니다. 

### Example Implementation in JavaScript
```c
if (index < simpleByteArray.length){
    index = simpleByteArray[index | 0];
    index = (((index * 4096) | 0) & (32*1024*1024 - 1)) | 0;
    localJunk ^= probeTable[index|0]|0;
}
```
위 코드는 Chrome 62.0.3202에서 테스트된 JavaScript PoC로, 브라우저 프로세스의 private memory를 읽을 수 있습니다.

Mistraining 단계에서 `index`는 범위 내 값으로, 공격 단계에서는 범위 밖 값으로 설정됩니다. `localJunk`는 코드가 최적화로 제거되지 않도록 하는 변수입니다. `|0` 연산은 값을 32비트 정수로 변환하여 JIT 컴파일러에게 최적화 힌트를 줍니다.

V8 엔진은 JIT 컴파일로 JavaScript를 기계어로 변환합니다. PoC 코드 주변에 dummy operation을 배치하여 `simpleByteArray.length`가 스택 메모리에 저장되도록 했고, 이를 통해 공격 시 캐시에서 축출할 수 있게 했습니다. JIT 컴파일러가 length parameter를 최적화해서 레지스터에 저장해버리면 캐시로 뭘 할 수가 없기 때문에, 코드를 복잡하게 만들어서 length를 스택에 담도록 유도하는 거입니다. <br>

![s2](/assets/img/posts/papers/spectre_2.png) <br>

JavaScript에서는 `clflush`를 사용할 수 없으므로 cache eviction을 이용합니다. 유출된 값은 `probeTable[n*4096]`의 캐시 상태로 전달되므로 256개 캐시 라인을 축출해서 캐시 라인들을 비워두어야 하고, `simpleByteArray.length`도 축출해야 합니다. JavaScript의 `performance.now()`는 정밀도가 의도적으로 낮춰져 있어서, HTML5 Web Worker로 별도 스레드를 만들어 공유 메모리 값을 반복 감소시키는 방식으로 고해상도 타이머를 구현했습니다. 

### Example Implementation Exploiting eBPF
본 연구에서는 eBPF 인터페이스를 악용하여 커널 메모리를 유출하는 PoC도 구현하였습니다. 프로세서가 SMAP을 지원하지 않는 것을 가정하나, SMAP이 있어도 공격이 가능합니다. eBPF는 커널 컨텍스트에서 커널이 검증한 eBPF 바이트코드를 실행할 수 있게 해줍니다. 본 공격에서는 **eBPF 코드를 투기적 실행에만 사용** 하고, covert channel 정보 복원은 유저 공간 코드로 수행합니다.

정상 실행에서는 eBPF의 경계 검사에 의해 범위 밖 접근이 차단되지만, 투기적 실행을 통해 이를 우회합니다. 커널 메모리의 배열에 범위 밖 인덱스로 투기적 접근을 하고, 인덱스를 충분히 크게 하여 유저 공간 메모리에 접근하게 합니다.

eBPF 서브시스템은 커널 메모리의 데이터 구조체를 관리하며, 사용자는 이를 생성하고 eBPF 바이트코드로 접근할 수 있습니다. 커널은 구조체마다 **메타데이터(배열 크기, 레퍼런스 카운트 등)를 저장** 하여 메모리 안전성을 검증합니다. 공격에서는 **false sharing** 을 이용해 경계 검사를 지연시킵니다. 커널이 배열 길이와 레퍼런스 카운트를 같은 캐시 라인에 저장하므로, 공격자가 다른 물리 코어에서 eBPF 프로그램을 반복적으로 로드/삭제하면 해당 캐시 라인이 다른 코어로 이동하여 경계 검사 지연을 유발합니다.

### Accuracy of Recovered Data
스펙터 공격은 높은 정확도로 데이터를 복원할 수 있지만, 에러가 발생할 수 있습니다. JavaScript나 ARM 플랫폼에서는 타이밍 측정 정확도가 낮아 여러 번 시도가 필요할 수 있고, 하드웨어 프리페칭이나 OS 활동으로 `array2`가 예기치 않게 캐시될 수 있습니다. 공격자는 캐시 히트가 없거나 2개 이상일 때 재시도하는 방식으로 보정합니다. 논문에서는 Intel Skylake와 Kaby Lake에서 약 0.005%의 에러율을 달성했습니다. 

## Variant 2: Poisoning Indirect Branches
간접 분기는 모든 아키텍처에서 흔하게 사용됩니다. 간접 분기 목적지 계산이 지연되면, 투기적 실행은 이전 실행 기록을 기반으로 목적지를 예측하여 진행합니다.

![s3](/assets/img/posts/papers/spectre_3.png)

위 그림처럼 스펙터 V2에서 공격자는 **branch predictor를 악의적인 주소로 mistrain** 하여, 투기적 실행이 원래라면 실행되지 않을 공격자가 정한 주소로 이어지게 합니다. 한 컨텍스트에서 predictor가 mistrain되면 다른 컨텍스트에도 영향을 미칩니다. BTB를 mistrain하려면 공격자가 자신의 주소 공간에서 피해자의 가젯과 **같은 가상 주소** 로 간접 분기를 반복 실행합니다. BTB는 가상 주소 기반으로 동작하므로 물리 주소나 프로세스 ID는 영향을 주지 않습니다.

간단한 예로, 간접 분기가 발생할 때 2개의 레지스터를 제어할 수 있는 공격자가 victim의 메모리를 읽으려는 상황을 생각할 수 있습니다. 2개인 이유는 **i) 어떤 비밀 값을 읽을지, ii) 캐시 흔적을 어디에 남길지** 모두 제어해야 하기 때문입니다. 이는 실제 바이너리에서 외부 입력을 다루는 함수에서도 흔하게 발생합니다. 공격자는 victim의 민감한 정보를 유출하는 **Spectre gadget** 도 찾아야 합니다. 

가젯의 구성 예시:
```
R1: 비밀 값 k가 있는 주소
R2: probeTable 베이스 주소

add R2, [R1]  ; 비밀 값 k를 읽어서 R2에 더함 (R2 = probeTable + k)
load [R2]     ; R2 주소에 접근하여 캐시에 흔적 남김
```

가젯은 victim의 executable 메모리 영역에 있어야 하지만, 대부분의 프로세스에 수많은 공유 라이브러리가 매핑되어 있어 가젯을 찾기는 어렵지 않습니다.

스펙터 공격은 다양한 변형이 가능합니다. 공격자가 제어할 수 있는 상태, 비밀 값의 위치(메모리, 레지스터, 스택 등), 투기적 실행 유도 방법, 사용 가능한 가젯, covert channel 유형에 따라 달라집니다. 예를 들어 비밀 값을 레지스터로 반환하는 암호 함수가 있다면, 해당 레지스터 값을 주소로 사용해 메모리에 접근하는 가젯만으로도 공격이 가능합니다.

### Mistraining branch predictors on x86 processors
공격자는 프로세서가 victim 코드를 실행할 때 투기적으로 가젯을 실행하도록 **공격자 컨텍스트에서 branch predictor를 mistrain** 합니다. CPU마다 mistraining 조건(프로세서가 참고하는 이전 분기 수, 사용하는 주소 비트 수 등)은 상이합니다. Branch predictor를 mistrain할 때는 물리 주소, 타이밍, 프로세스 ID와 관계없이 **가상 주소만 일치** 하면 되고, **같은 CPU 코어** 에서 진행되어야 합니다. 또한 잘못된(illegal) 목적지로 점프해도 BTB가 학습하기 때문에, 공격자가 exception handler로 예외를 처리하면서 훈련을 반복하면, 피해자 프로세스의 간접 분기도 같은 가상 주소(가젯)로 투기적 점프를 하게 됩니다.

### A. Experimental Results
V1과 마찬가지로 Intel, AMD, ARM 프로세서에 걸쳐 다양한 OS와 하이퍼바이저에서 indirect branch poisoning 공격이 작동하는 것을 확인하였습니다. 공격이 얼마나 효과적인지 측정하기 위해 테스트용 victim 프로그림을 만들어 32개의 간접 점프를 반복 실행하고, 원래는 절대로 실행되지 않을 가젯을 만들어 32번째 점프에서 가젯 주소로 점프하는지 확인하도록 하였습니다. 공격 프로그램은 31 회의 점프를 victim과 똑같이 하고 마지막 점프만 가젯 주소로 점프하도록 하여 학습을 시켰습니다. 실험 결과 indirect branch poisoning은 충분히 효과적이고 속도도 빠르다는 것을 입증할 수 있었습니다.

### B. Indirect Branch Poisoning Proof-of-Concept on Windows
개념 증명을 위해 **비밀 키와 입력 파일의 헤더를 합쳐서 SHA-1 해시를 계산하는** 간단한 피해자 프로그램을 만들었습니다. 이 프로그램은 루프를 돌면서 Sleep(0)을 호출하고, 파일에서 입력을 로드한 다음 SHA-1을 계산하여 해시를 출력합니다. `Sleep()` 호출 시점에 ebx, edi 레지스터에는 **파일의 데이터(공격자가 조작 가능)** 가, edx에는 공격자가 알고 있는 값이 들어있는 것을 확인했고, 이는 스펙터 가젯의 조건(두 레지스터 제어)을 만족합니다.

실행 가능한 메모리 영역을 조사한 결과 `ntdll.dll`에서 다음과 같은 스펙터 가젯을 발견하였습니다. Windows에서는 DLL의 어떤 페이지들은 메모리에는 있지만 사용하려면 soft page fault를 통해 working set에 포함되어야 하는 경우가 있어, 공격자 프로세스의 working set을 분석하여, working set에 속해있는 페이지에 있는 가젯을 찾아서 사용하였습니다.
```
adc edi, dword ptr [ebx+edx+13BE13BDh]
adc dl, byte ptr [edi]
```

ebx, edi를 제어할 수 있는 상태에서 **이 가젯을 투기적으로 실행하면 victim 메모리에 대한 임의 읽기** 가 가능합니다. 공격자는 edi를 probe 배열의 베이스 주소로, ebx를 `m - 0x13BE13BD - edx`로 설정합니다. 첫 번째 명령어는 주소 m에서 32비트 값을 읽어 edi에 더하고, 두 번째 명령어는 edi가 가리키는 주소(probe 배열 + 읽은 값)에 접근하여 캐시에 흔적을 남깁니다. 가젯이 32비트 값을 읽어오기 때문에, 이론상 $2^32$가지 가능한 값에 대해 Flush+Reload를 적용하려면 비현실적으로 많이 체크를 해야하지만, 만약 m+2, m+3 바이트를 알고 있다고 하면 훨씬 작은 영역으로 매핑하여 probe 할 수 있습니다.

Indirect branch poisoning을 할 때는 `jmp dword ptr ds:[76AE0078h]` 형태를 하고 있는 `Sleep()` 함수의 첫 번째 instruction을 대상으로 하였습니다. 가젯의 투기 실행을 유도하기 위해 jump를 포함하고 있는 메모리 주소는 캐시에서 flush 시키고 predictor를 mistrain 하였습니다. clflush가 통하지 않아 점프 목적 주소를 담고 있는 메모리를 주기적으로 evict 하기 위한 별도의 스레드를 실행하였습니다. CoW가 발생하면서 victim과 attack process가 보는 물리 주소가 달라지기 때문에 Evcition은 JavaScript 예시처럼 페이지의 하위 12 비트는 일정하다는 점을 이용해서, 가상 주소 기준으로 4096 바이트 단위로 축출 합니다. 

Victim과 같은 코어에서 돌아가는 branch predictor를 mistrain하는 쓰레드는 단순히 간접 분기만 학습 시키는게 아니라 분기 히스토리까지 맞춰주어야 합니다. 실험에서 사용하는 프로세서는 주소의 하위 20비트만을 참고하기 때문에, $2^20$ 바이트 크기의 실행 가능한 메모리 영역을 `ret` 명령어로 덮은 다음 victim의 메모리 접근 히스토리와 별도로 알아낸 ASLR 정보를 결합해 스택에 주소들을 넣어서 ret 명령어들로 victim의 히스토리를 만들어낼 수 있습니다. 이런 방식으로 주소의 하위 20비트를 분기 히스토리까지 일치시켜 학습시킬 수 있습니다. 

공격자는 어디를 읽을지 정하는 `ebx`와 읽은 데이터를 어디에 저장할지 정하는 `edi` 레지스터 값을 정한 다음 Flush+Reload 기법을 사용하여 victim 프로세스가 접근한 메모리를 추론할 수 있습니다. 그러나 4096을 곱했던 예시 코드와 다르게 실제 가젯은 캐시 라인의 크기가 64 바이트이기에 하위 6비트의 정보가 무시됩니다. 이를 구분하기 위해 probe array의 베이스 주소를 한칸씩 옮기면서 다음 캐시 라인을 건드리는 순간을 잡아내고, 이를 통해 하위 6비트를 계산합니다.

### C. Reverse-Engineering Branch Prediction Internals
![s4](/assets/img/posts/papers/spectre_4.png) <br>

본 연구에서는 KVM 공격을 진행하기 전에 Intel Haswell branch predictor 내부 구조를 역공학하였는데, 이는 mistraining을 최적화하는데 도움이 되었습니다. 

**Branch History Buffer (BHB)** 는 패턴 히스토리 개념을 논리적으로 확장한 형태입니다. BHB는 명령어 히스토리를 기반으로 예측을 수행하면서도, 단순성과 rolling hash 속성(새 데이터가 들어올 때 전체를 다시 계산하지 않고 효율적으로 업데이트되는 해시)을 유지합니다. 

Branch predictor에 사용되는 정확한 함수를 알아내기 위해 **predictor collision** 을 활용하였는데, 같은 코드를 실행하는 두 하이퍼스레드를 준비하고, hyperthread A의 프로세스는 타겟 주소 1로, hyperthread B의 프로세스는 타겟 주소 2로 점프하도록 설정하였습니다. 또한 투기적 실행으로 인한 오예측을 탐지할 수 있도록, hyperthread A에서는 주소 2로 **잘못 점프했을 때 특정 캐시 라인을 로드** 하는 코드를 배치하여 오예측 비율(misprediction rate)을 측정하였습니다. 이 비율이 높다는 건 프로세서가 두 분기를 구분하지 못한다는 것을, 반대로 낮으면 프로세서가 잘 구분하는 것을 의미합니다. 한 스레드의 타겟 주소에 비트 플립 등의 조작을 가하고 오예측률의 변화를 관찰하였으며, 이를 통해 **어떤 비트가 분기 예측에 영향을 주는지와 어떤 비트들이 XOR되어 사용되는지** 를 확인하였습니다.

### D. Attack against KVM
리눅스 커널 4.9.30을 실행 중인 Intel Xeon Haswell 환경에서, 공격자가 guest ring 0 권한을 가지고 있을 때, 호스트(hypervisor)의 메모리를 유출하는 공격을 수행하였습니다. 먼저 BHB와 BTB의 정보 누출을 분석하여 hypervisor ASLR 위치를 파악합니다. 그 후 branch target injection을 통해 스펙터 가젯을 실행시켜 L3 캐시 set association 정보와 물리 메모리 매핑 정보를 수집합니다. 마지막으로 **hypervisor 메모리 내의 eBPF 인터프리터에서 실행되는 스펙터 가젯** 을 이용하여 하이퍼바이저의 메모리를 유출합니다.

## Variations
지금까지 투기적 실행이 캐시 상태에 주는 변화를 활용하는 공격들에 대해 알아보았는데, 이번 섹션에서는 투기적 실행이 남기는 어떤 효과라도 잠재적으로 정보 유출 공격에 사용될 수 있음을 보여줍니다. 

### Spectre variant 4
Speculative Store Bypass(SSB)라고도 불리는 스펙터 V4는 store-to-load forwarding logic에서 발생하는 speculation을 활용합니다. 프로세서가 어떤 메모리를 load할 때 이 load가 이전 store와 관련 없다고 잘못 추측하게 되면, 오래된 값이나 다른 값을 읽어 그 값으로 투기적 실행을 진행하게 되고, 캐시에 흔적을 남기게 됩니다. 

```
mov [rdi+rcx],al
movzx r8,byte [rsi+rcx]
shl r8,byte 0xc
mov eax,[rdx+r8]
```
레지스터 `rdi`와 `rsi`는 정상 실행 경로에서는 같은 주소를 가리킨다고 가정을 합니다. 즉, 라인 2는 사실은 라인 1에 의존해야 합니다. 만약 라인 1의 주소를 계산하는데 시간이 오래 걸릴 때 프로세서가 movzx가 mov에 의존하지 않는다고 잘못 추측하게 되면, rsi+rcx 메모리에 위치한 알 수 없는 값이 r8에 로드가 되고 라인 4에 그대로 들어갑니다. 그리고 만약 r8이 민감한 값이었다면 Flush+Reload 같은 기법으로 이를 알아낼 수 있게 됩니다. 

### Evict+Time
```
if (false but mispredicts as true)
    read array1[R1]
    read [R2]
```

R1 레지스터가 비밀 값을 가지고 있다고 가정합니다. 만약 투기적으로 실행된 array1[R1] 읽기가 cache hit이었다면 메모리 버스를 사용하지 않아 바로 다음 [R2] 읽기가 빠르게 시작되지만, cache miss라면 메모리 버스를 점유하게 되어 [R2] 읽기가 지연됩니다. 공격자는 victim thread의 전체 실행 시간을 측정하여 이 타이밍 차이를 감지할 수 있습니다. 또한 시스템의 다른 컴포넌트(다른 프로세서 등)도 메모리 버스 활동이나 DRAM row address 변경 같은 부수 효과를 감지할 수 있습니다. 이 공격은 투기적 실행이 캐시 **내용을 수정** 하지 못하게 막더라도, 캐시 **상태가 타이밍에 영향을 주는 것** 까지는 막기 어렵기 때문에 방어가 더 어렵습니다.

### Instruction Timing
```
if (false but mispredicts as true)
    multiply R1, R2
multiply R3, R4
```

스펙터 공격은 반드시 캐시를 사용할 필요는 없습니다. 위 코드에서 multiplier가 투기적으로 실행된 `multiply R1, R2`를 처리하는 동안, `multiply R3, R4`는 multiplier가 사용 가능해질 때까지 대기해야 합니다. 첫 번째 곱셈의 수행 시간은 피연산자 값(R1, R2)에 따라 달라질 수 있으며, 이러한 타이밍 차이가 두 번째 곱셈의 시작 시점에 영향을 줌으로써 R1, R2에 대한 정보를 유출할 수 있습니다.

### Contention on the Register File
```
if (false but mispredicts as true)
    if (condition on R1)
        if (condition)
```

CPU가 투기적 실행의 체크포인트를 저장하기 위해 사용할 수 있는 레지스터 개수가 제한되어 있다면, 중첩된 조건문의 깊이에 따라 필요한 체크포인트 수가 달라집니다. `condition on R1`이 참일 때는 더 깊은 중첩으로 인해 더 많은 체크포인트가 생성되고, 거짓일 때는 적게 생성됩니다. 공격자가 레지스터 파일의 contention(경합)을 타이밍이나 다른 부수 효과로 감지할 수 있다면, 이를 통해 R1 값에 대한 정보를 추론할 수 있습니다.

### Variations on Speculative Execution
조건 분기가 없는 코드도 잠재적으로 취약할 수 있습니다. 예를 들어, 공격자가 레지스터 R1의 값이 특정 값 X와 같은지 알고 싶다고 가정합니다. 이러한 단일 비트 정보만으로도 암호 구현을 공격할 수 있습니다. 공격자는 인터럽트 발생 후 **복귀 주소를 조작하여(mistrain)**, 인터럽트 핸들러가 `load [R1]` 같은 명령어로 잘못 복귀하도록 만들 수 있습니다. 이후 Flush+Reload 기법으로 메모리 주소 X가 접근되었는지 확인하면 R1이 X였는지 여부를 알아낼 수 있습니다.

### Leveraging Arbitrary Observable Effects
사실상 투기적 실행이 만들어내는 어떤 부수 효과든 covert channel을 구성하여 정보를 유출하는 데 사용할 수 있습니다. 
```
if (x < array1_size) {
    y = array2[array1[x] * 4096];
    // do something detectable when
    // speculatively executed
}
```

위 코드가 투기적 실행 중 캐시에 새로운 데이터를 적재하지 못하는 프로세서에서 실행된다고 가정해봅시다. 이 경우에도 투기적 실행에 진입할 때의 캐시 상태에 따라 `array2` 접근 시간이 달라지며, 이는 후속 투기적 실행의 지속 시간이나 타이밍에 영향을 줍니다. 최종적으로 관측 가능한 흔적을 남기는 연산은 캐시뿐만 아니라, 리소스 경합(버스, 연산 유닛 등), 전자기 복사, 전력 소비 등 **다양한 side channel이나 covert channel을 통해 구현** 될 수 있습니다.

## Mitigation Options
### A. Preventing Speculative Execution
제어 흐름이 확정될 때까지 투기적 실행을 금지하면 Spectre 공격을 효과적으로 방어할 수 있으나 성능에 심각한 저하가 발생합니다. 대신 소프트웨어가 **serializing instruction** 또는 **speculation blocking instruction** 을 사용하여 특정 명령어들이 투기적으로 실행되지 않고 순차적으로 실행되도록 강제할 수 있습니다. 예를 들어 Intel과 AMD의 `lfence` 명령어는 조건 분기 후 투기적 실행을 차단하여 Spectre variant 1을 효과적으로 방어할 수 있지만, 모든 조건 분기에 이 명령어를 추가하면 성능에 큰 악영향을 줍니다. 정적 분석을 통해 실제로 취약한 분기만 식별하여 필요한 speculation blocking instruction의 개수를 줄이는 방법도 제안되었습니다.

간접 분기 전에 serializing instruction을 삽입하는 것은 indirect branch poisoning 방어에도 도움이 될 수 있습니다. 간접 분기 직전에 `lfence`를 삽입하면 이전 명령어들이 모두 완료된 후 분기 목적지 주소가 확정되므로, 분기 예측기가 잘못 학습되어 있더라도 투기적으로 실행되는 명령어의 수를 크게 줄일 수 있습니다.

이러한 접근 방식들은 잠재적으로 취약한 모든 코드(운영체제, 라이브러리, 애플리케이션 등)에 적절한 패치가 적용되어야 함을 의미하며, 광범위한 소프트웨어 업데이트가 필요합니다.

### B. Preventing Access to Secret Data
투기적으로 실행된 코드가 민감한 데이터에 접근하지 못하도록 막는 방법들도 Spectre 공격을 방어할 수 있습니다. Chrome 브라우저는 각 웹사이트를 별개의 프로세스에서 실행하는데, Spectre 공격은 victim의 권한 내에서 접근 가능한 영역에만 작동하기 때문에 앞서 설명한 JavaScript 공격으로는 다른 프로세스의 메모리를 읽을 수 없습니다.

WebKit의 경우 투기적으로 실행된 코드가 비밀 값에 접근하는 것을 제한하기 위해 두 가지 전략을 사용합니다. 첫 번째는 배열 인덱스의 일부 비트만 사용하도록 비트 마스킹을 적용하는 것입니다. 여전히 out-of-bounds 접근은 가능하지만, **접근 범위를 배열 근처 메모리로 제한** 하여 임의의 먼 메모리 접근을 방지합니다. 두 번째는 포인터를 random poison 값으로 XOR 처리하는 것입니다. 이 기법이 적용되면 poison 값을 모르는 공격자는 XOR 처리된 포인터를 사용할 수 없고, 투기적 실행 과정에서 포인터의 타입이 잘못 예측되면 올바르지 않은 poison 값이 사용되면서 포인터가 쓰레기 주소를 가리키게 됩니다.

### D. Limiting Data Extraction from Covert Channels
Covert channel을 통한 데이터 유출을 제한하는 방법들도 여럿 제시되었습니다. JavaScript 기반 공격의 경우, 주요 브라우저들은 고해상도 타이머의 정밀도를 낮추고, 타이밍 측정에 사용될 수 있는 `SharedArrayBuffer`를 비활성화하였습니다. 그러나 이러한 조치들에도 불구하고 현대 프로세서들은 covert channel을 근본적으로 제거할 메커니즘을 갖추고 있지 않기 때문에, 공격을 완전히 방어할 수 있다고 보장하기 어렵습니다.

### E. Preventing Branch Poisoning
Indirect branch poisoning을 막기 위해 Intel과 AMD는 ISA를 확장하여 간접 분기를 제어하는 메커니즘을 도입하였습니다. 이 메커니즘은 세 가지 제어로 이루어집니다.

첫 번째는 **Indirect Branch Restricted Speculation (IBRS)** 입니다. IBRS는 낮은 권한 레벨에서의 간접 분기 학습이 높은 권한 레벨의 코드 실행에 영향을 주는 것을 방지합니다. 프로세서가 IBRS 모드에 진입하면, IBRS 모드 진입 이전의 분기 예측 상태로부터 영향을 받지 않습니다. 두 번째는 **Single Thread Indirect Branch Prediction (STIBP)** 입니다. STIBP는 같은 물리 코어에서 동작하는 두 하이퍼스레드 간의 간접 분기 예측기 공유를 막습니다. 마지막으로 **Indirect Branch Predictor Barrier (IBPB)** 는 분기 예측기 상태를 초기화하는 barrier로, barrier 이전에 실행된 소프트웨어가 barrier 이후에 실행되는 소프트웨어의 분기 예측에 영향을 주지 못하도록 BTB를 flush합니다.

Google은 대안으로 **retpoline** 메커니즘을 제안하였습니다. Retpoline은 간접 분기를 return 명령어를 사용하는 코드 시퀀스로 대체합니다. Return 명령어가 투기적으로 실행될 때는 무한 루프로 진입하여 유용한 작업을 수행하지 못하게 하고, 실제 실행 시에는 스택에 저장된 목적지 주소를 사용하여 정상적으로 점프합니다. 이에 대하여 인텔은 추측에 실패했을 때 BTB로 `fall-back` 하는 특정 CPU들에 대하여 fall-back 메커니즘을 제거하는 마이크로코드 업데이트를 하였습니다. 