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
    y = array2[array][x] * 4096;
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
