---
title: "Software Grand Exposure: SGX Cache Attacks Are Practical"
date: 2026-02-20 00:00:00 +0900
categories: [Papers]
tags: [security, side channel, TEE]
permalink: /posts/Software-Grand-Exposure/
math: true
---

# Summary for Software Grand Exposure: SGX Cache Attacks Are Practical

## Introduction
Intel SGX는 enclave라는 격리된 실행 환경을 제공하여 OS의 메모리 직접 접근/조작을 차단합니다. 그러나 최근 연구들은 다양한 부채널을 통해 격리된 enclave로부터 정보를 유출할 수 있음을 보여주고 있습니다.

한 가지 유형은 페이지 폴트를 이용하는 것입니다. SGX는 페이징을 포함한 메모리 관리를 비신뢰 OS에게 맡기는데, OS는 페이지 폴트를 강제로 발생시킨 다음 요청된 페이지들을 통해 enclave 내부의 실행 흐름이나 데이터 접근 패턴을 알아낼 수 있습니다([Controlled-Channel](https://jihooniab1.github.io/posts/Controlled-Channel/)). 다른 유형은 enclave와 비신뢰 소프트웨어 사이에 공유되는 캐시를 이용하는 것으로, 최근 SGX 플랫폼을 대상으로 한 캐시 기반 공격들이 활발히 연구되고 있습니다.

이러한 information leakage 문제에 대한 다양한 방어 기법들이 제안되었습니다. T-SGX와 Déjà Vu는 OS가 enclave 실행 도중 페이지 폴트나 인터럽트를 이용하여 개입할 때 이를 탐지하고 방어합니다. Sanctum과 같이 하드웨어를 새롭게 설계하여 정보 유출을 원천 차단하려는 시도도 있었습니다.

본 연구에서 제안하는 공격은 victim enclave와 공격자가 **인터럽트 없이 병렬로 실행** 되기 때문에 enclave가 공격을 인지하거나 방어할 수 없습니다. 또한 기존 일부 공격들과 달리 victim과 공격자 사이의 **동기화도 필요하지 않습니다.** 인터럽트 없이 공격을 수행하면 캐시 모니터링 과정에서 많은 노이즈가 발생하는데, 이를 줄이기 위해 victim 프로세스를 전용 코어에 격리하고, 공격과 무관한 인터럽트(benign interrupt)를 최소화하며, CPU performance counter를 활용해 정밀한 캐시 모니터링을 수행합니다.

공격의 유효성을 입증하기 위해 두 가지 케이스 스터디를 진행하였습니다. 첫 번째는 RSA 복호화로, 약 300회의 반복 복호화를 통해 2048비트 private key의 70%를 추출하였습니다. 그러나 이러한 캐시 공격은 애플리케이션 레벨에서 방어가 가능합니다. 예를 들어 `scatter-gather` 기법은 secret-dependent 테이블 접근 시 항상 모든 캐시 라인을 건드려 **공격자가 접근 패턴을 구분할 수 없게** 만듭니다. SGX SDK 역시 scatter-gather가 적용된 암호 알고리즘을 제공하므로, 암호화 연산을 대상으로 하는 캐시 공격은 실제로는 위협이 제한적일 수 있습니다.

그러나 scatter-gather 같은 기법은 보안 전문 지식과 상당한 개발 노력을 필요로 하기 때문에, 민감한 정보를 다루는 enclave라도 이러한 방어가 적용되지 않은 경우가 충분히 존재할 수 있습니다. 두 번째 케이스 스터디에서는 **genome indexing 알고리즘인 PRIMEX** 를 실행하는 enclave를 대상으로 공격을 수행하여, 처리 중인 DNA의 STR(Short Tandem Repeat) 정보를 추출하고 높은 확률로 개인을 식별할 수 있음을 보입니다.

## Background
### Intel SGX
SGX는 격리된 컴포넌트인 enclave를 만들고 관리하는 새로운 CPU instruction 집합을 도입합니다. SGX는 CPU만을 유일하게 신뢰 가능한 하드웨어 컴포넌트로 간주하기 때문에, enclave data는 CPU 캐시, 레지스터 안에서만 평문으로 취급되고, DRAM과 같은 CPU 외부로 나갈 때는 암호화되고 무결성이 보호됩니다. OS는 신뢰되지는 않지만 enclave 생성 및 관리, 메모리 할당, enclave 메모리의 주소 변환, enclave 초기화 등을 수행합니다. 그러나 OS의 action들은 SGX에 의해 기록되고 외부의 **원격 증명(remote attestation)** 을 통해 검증될 수 있습니다. OS는 다른 프로세스처럼 enclave도 인터럽트하고 재개할 수 있는데, SGX는 정보 유출을 막기 위해 하드웨어가 enclave의 context를 저장하고, 레지스터 내용을 초기화한 뒤 OS에 제어권을 넘기는 AEX(Asynchronous Enclave Exit)를 수행합니다. enclave가 재개될 때도 하드웨어가 context 복구를 담당하여 조작을 방지합니다.

### Cache Architecture
캐시는 최근에 처리한 데이터의 복사본을 저장하여 DRAM 접근에 필요한 지연 시간을 줄입니다. 메모리 연산을 수행할 때 캐시 컨트롤러는 요청된 데이터가 캐시되어 있는지 확인하여 유무에 따라 cache hit/miss가 발생합니다. 캐시는 cache line들로 나뉘고, 메모리 주소의 하위 비트가 cache line을 결정하기 때문에 여러 메모리 주소가 같은 cache line에 매핑됩니다. 충돌을 줄이기 위해 캐시는 set-associative 구조를 가지며, 각 cache line에 여러 개의 복사본(cache set)이 존재합니다.

현재 Intel CPU는 3단계 캐시 계층 구조를 가집니다. L3(LLC)는 가장 크고 느리며 모든 코어가 공유합니다. L1/L2는 각 코어에 전용으로 할당되지만, 같은 코어의 SMT(하이퍼스레딩) 실행 유닛들 사이에서는 공유됩니다. L1 캐시의 특징은 data cache(L1D)와 instruction cache(L1I)로 분리되어 있다는 점으로, 코드 fetch는 data cache에 영향을 주지 않고 그 반대도 마찬가지입니다. L2, L3에서는 코드와 데이터가 같은 캐시 공간을 두고 경쟁합니다.

### Performance Monitoring Counters
PMC는 하드웨어 이벤트를 기록하는 CPU 기능으로, 소프트웨어 개발자가 프로그램이 하드웨어에 미치는 영향을 파악하여 최적화할 수 있도록 돕습니다. CPU는 여러 PMC를 갖고 있는데, 실행된 사이클, 캐시 hit/miss, 예측이 틀린 분기 등 다양한 이벤트를 모니터링하도록 설정될 수 있습니다. PMC는 MSR에 쓰기를 하여 모니터링할 대상과 연산 모드를 설정하며, 읽을 때는 RDPMC(Read Performance Monitoring Counters) 명령어를 사용합니다. MSR 쓰기는 특권 소프트웨어만 가능하므로 PMC 설정은 OS 권한을 필요로 합니다.

PMC가 기록하는 하드웨어 이벤트는 부채널에 악용될 수 있기 때문에, SGX enclave는 **Anti Side-channel Interference (ASCI)** 기능을 활성화하여 fixed cycle counter를 제외한 enclave 내부의 하드웨어 이벤트 모니터링을 차단할 수 있습니다.

## System and Adversary Model
![s1](/assets/img/posts/papers/softgrand_1.png) <br>

위 그림은 공격자 모델을 간단하게 나타낸 모습입니다. 공격자에게 장악된 OS가 있는 시스템에서 실행되는 enclave가 공격자 프로세스와 CPU 코어를 공유하고 있는 상태입니다.

공격자는 enclave 내부에서 실행되는 소프트웨어를 제외한 시스템에 대한 모든 제어권을 갖고 있으며, enclave 내부를 제어할 수는 없지만 enclave의 **초기 상태(코드, 데이터)와 메모리-캐시 매핑을 파악** 하고 있어 enclave를 마음대로 재시작하고 같은 입력을 반복해서 줄 수 있습니다. 나아가서 실행 시간, 실행되는 CPU 코어와 같이 enclave에 할당하는 자원도 제어할 수 있고, 타이머 빈도나 인터럽트 핸들러와 같은 시스템 하드웨어도 임의로 설정할 수 있습니다. 그러나 enclave 내부 메모리에 직접 접근할 수는 없고, 인터럽트 후 레지스터 상태도 얻을 수 없습니다.

공격자의 목표는 공격자 프로세스의 캐시 상태 변화를 통해 **victim enclave의 캐시 사용 패턴을 파악** 하는 것입니다. victim의 메모리-캐시 매핑을 사전에 알고 있기 때문에, 어느 캐시 라인에서 eviction이 발생했는지 관찰함으로써 victim이 어떤 메모리 주소에 접근했는지 역추론할 수 있고, 나아가 enclave가 처리하는 민감한 데이터까지 추론할 수 있습니다. 

## Our Attack Design
### Prime+Probe
![s2](/assets/img/posts/papers/softgrand_2.png) <br>

위 그림은 Prime+Probe 공격의 주요 단계를 나타냅니다. 먼저 공격자는 메모리 접근을 통해 캐시 전체에 공격자 프로세스의 데이터를 채우는 방식으로 캐시를 **prime** 합니다. 그 후에 victim은 secret-dependent하게 메모리에 접근합니다. 예시 그림에서는 key-bit가 0일 때 주소 X를 읽게 되고, 주소 X는 `cache line 2`에 매핑되어 있어 주소 X의 데이터가 로드되면서 기존 데이터가 축출됩니다. 이후 공격자는 **probe** 를 통해 어느 캐시 라인이 축출되었는지 알아내는데, 각 캐시 라인에 매핑된 메모리를 읽으면서 접근 시간을 측정하여 느린 경우 해당 캐시 라인이 축출되었음을 알아냅니다.

공격자는 사전에 파악한 victim의 메모리-캐시 매핑을 바탕으로, 어느 캐시 라인이 축출됐는지를 통해 victim이 어떤 메모리 주소에 접근했는지 역추론합니다. 예시에서는 `cache line 2`가 축출되었으므로 주소 X가 접근되었고, 따라서 key-bit가 0임을 알 수 있습니다. 이 과정을 각 key-bit마다 반복하여 전체 키를 복원합니다.

### Prime+Probe for SGX
Prime+Probe와 같은 캐시 부채널 기법들은 노이즈에 영향을 많이 받기 때문에, 보통 전체 암호화 키를 추출하기 위해 수천~수백만 번의 반복 실행이 필요합니다. 본 연구의 목표는 훨씬 적은 실행 횟수로도 작동하는 효율적인 공격을 구성하는 것으로, 캐시 모니터링 채널의 노이즈를 줄이는 것이 핵심입니다.

노이즈 감소 기법을 선택할 때 두 가지 조건이 있습니다. 첫째, 최근 제안된 방어 기법(T-SGX, Déjà Vu)에 탐지되지 않으려면 인터럽트를 사용해서는 안 됩니다. 둘째, 공격자가 OS를 장악하고 있으므로 일반적인 공격자는 접근할 수 없었던 performance counter와 같은 특권적인 방법을 활용할 수 있습니다. 

이러한 조건 하에 공격 실현의 주요 과제들을 다음과 같이 정리할 수 있습니다.

1. 다른 task로 인한 cache pollution 최소화
2. victim 자신의 메모리 접근으로 인한 cache pollution 최소화
3. enclave가 공격을 인지하지 못하도록 인터럽트 없이 victim을 실행
4. 타이밍 측정의 노이즈 없이 캐시 축출을 정확히 식별
5. victim의 메모리 접근을 놓치지 않도록 높은 빈도로 캐시 모니터링 수행

### Noise Reduction Techniques
#### Isolated attack core
노이즈를 최소화하기 위해 지정된 CPU 코어에서 victim과 Prime+Probe 코드만 실행하도록 하였습니다. Linux 스케줄러를 수정하여 지정된 코어(**attacker core**)에서는 victim과 attacker 코드만 실행되고 다른 프로세스의 실행을 막아 L1/L2 캐시 오염을 방지합니다.

#### Self-pollution
victim의 공격과 관련 없는 메모리 접근이 노이즈를 발생시키지 않도록 본 공격에서는 L1 캐시를 활용합니다. L1 캐시는 데이터 캐시(L1D)와 명령어 캐시(L1I)로 분리되어 있기 때문에, 코드 접근은 코드의 위치와 관계없이 데이터 캐시 라인에 영향을 주지 않습니다. 따라서 공격자가 관측하는 캐시 라인은 victim의 **데이터 접근** 에 의해서만 오염됩니다.

#### Uninterrupted execution
victim을 인터럽트하면 두 가지 문제가 발생합니다. 첫째, AEX가 수행되고 ISR이 호출되는 과정에서 캐시 오염으로 인한 노이즈가 발생합니다. 둘째, T-SGX, Déjà Vu와 같은 방어 기법들은 인터럽트 발생을 감지하여 공격을 탐지합니다. 따라서 enclave를 인터럽트 없이 실행시키면 enclave는 공격을 인지하지 못하게 됩니다.

victim의 캐시 변화를 실시간으로 관측하려면 attacker code가 같은 코어에서 병렬로 실행되어야 합니다. 이를 위해 첫 번째 SMT 실행 유닛에는 victim을, 두 번째 유닛에는 attacker code를 실행시킵니다. 두 코드가 L1 캐시를 경합하는 과정에서 victim의 캐시 접근 패턴을 파악할 수 있게 됩니다.

인터럽트는 네트워크 패킷 수신, 사용자 입력 등 다양한 이유로 자주 발생하며, 기본적으로 모든 CPU 코어에서 처리됩니다. attacker code 역시 인터럽트에 의해 방해받을 수 있으므로, attacker core로는 인터럽트가 전달되지 않도록 인터럽트 컨트롤러를 설정하였습니다. 단, 타이머 인터럽트는 해당 코어에서만 처리가 가능하므로 완전히 차단할 수 없습니다. 대신 타이머 인터럽트 주파수를 100Hz로 낮춰 10ms의 시간 프레임 안에서 attack cycle이 방해 없이 완료될 수 있도록 하였습니다.

#### Monitoring cache evictions
기존의 Prime+Probe 공격에서 공격자는 특정 캐시 라인에 매핑된 메모리 접근 시간을 측정하여 eviction 여부를 판단합니다. 그러나 이 방식은 두 가지 문제가 있습니다. 첫째, 시간 측정 자체가 추가적인 노이즈를 유발합니다. 둘째, L1 cache hit은 4사이클, L2 cache hit은 12사이클로 그 차이가 매우 작아 타임스탬프 카운터(RDTSC) 측정의 노이즈가 이 차이와 비슷한 수준이기 때문에, L1 hit과 L1 miss를 구분하기가 어렵습니다.

이러한 문제를 해결하기 위해 본 연구에서는 타이밍 측정 대신 PMC를 사용하여 cache miss 이벤트를 직접 카운팅합니다. Intel 프로세서의 ASCI 기능이 enclave 내부에서 발생하는 하드웨어 이벤트의 모니터링을 차단하지만, 본 공격은 enclave의 캐시 활동을 직접 모니터링하는 것이 아니라 **캐시를 공유하는 attacker process 자신의 cache miss 이벤트** 를 관측하는 것이므로 ASCI의 영향을 받지 않습니다.

#### Monitoring frequency
victim이 인터럽트 없이 실행되는 동안 캐시 이벤트를 놓치지 않으려면 Prime+Probe를 높은 빈도로 수행해야 합니다. 그러나 매 사이클마다 모든 캐시 라인의 eviction 여부를 확인하는 것은 시간이 너무 오래 걸려 sampling rate가 낮아지는 문제가 있습니다.

이를 해결하기 위해 한 번의 실행에서 **특정 캐시 라인(또는 소수의 캐시 라인)만 집중적으로 모니터링** 합니다. 1회차 실행에서는 캐시 라인 0, 2회차에서는 캐시 라인 1을 모니터링하는 방식으로, 여러 실행 결과를 정렬하여 합치면 전체 캐시 접근 패턴을 복원할 수 있습니다. 이 방식이 가능한 이유는 공격자가 enclave를 마음대로 반복 실행할 수 있고, 같은 입력에 대해 enclave의 실행이 결정론적이기 때문입니다.

## Attack Instantiations
실험 플랫폼은 Intel Core i7-6600U CPU, Linux 14.04, 커스텀 4.4.0-57 커널, SGX SDK 1.6을 탑재한 Dell Latitude E5470입니다. 두 가지 공격을 구현하고 평가하였습니다.

#### RSA
첫 번째 공격은 RSA 복호화 연산을 대상으로 하였습니다. SGX SDK 1.6의 표준 fixed-window RSA 구현을 공격하였으며, 이 구현은 CRT(Chinese Remainder Theorem) 최적화를 사용하여 복호화 시 1024비트 지수 연산을 두 번 수행합니다. 사전 계산 테이블(pre-computed multiplier table)에 대한 개인키 의존적 메모리 접근을 모니터링하여, 약 300회의 반복 복호화로부터 2048비트 개인키의 70%를 추출할 수 있었습니다. 추출된 70%만으로도 전체 키를 효율적으로 복원할 수 있습니다.

#### Genomic attack
많은 암호화 라이브러리들은 scatter-gather와 같은 기법으로 캐시 부채널 공격에 대한 방어가 적용되어 있으며, SGX SDK 역시 이러한 라이브러리를 제공합니다. 그러나 이러한 방어 기법은 전문 지식과 상당한 노력을 필요로 하기 때문에 모든 enclave에 적용되기는 어렵습니다. 보안 전문가가 아닌 개발자가 작성한 비암호화 애플리케이션은 특히 취약할 수 있습니다.

두 번째 공격은 이를 보여주기 위해 genomic processing enclave를 대상으로 수행하였습니다. 게놈 데이터는 클라우드 컴퓨팅의 이점을 크게 활용할 수 있는 분야이지만, 동시에 개인 식별과 질병 소인 파악에 활용될 수 있는 매우 민감한 정보입니다. 따라서 신뢰할 수 없는 클라우드 환경에서 게놈 데이터의 기밀성을 유지하는 것은 매우 중요합니다.

게놈 서열은 아데닌(A), 사이토신(C), 구아닌(G), 타이민(T) 네 가지 뉴클레오타이드의 순서로 표현됩니다. `Microsatellite 또는 STR(Short Tandem Repeat)`은 **특정 뉴클레오타이드 서열이 연속으로 반복** 되는 구간을 말합니다. STR 분석은 흔한 게놈 포렌식 기법으로 미국 법의학에서는 13개의 표준 위치에서 STR 길이를 조합하여 개인을 식별합니다.

### Victim Enclave
![s3](/assets/img/posts/papers/softgrand_3.png) <br>

게놈 시퀀스를 효율적으로 검색하는 것은 분석에서 중요한 부분이기 때문에, 보통 게놈 데이터는 실제 분석이 수행되기 전에 먼저 전처리됩니다. 전처리 방법 중 흔하게 사용되는 방법은 게놈 시퀀스를 **길이가 k인 부분 문자열, k-mer** 로 나누는 것입니다. 

위 그림에서 입력 `ATCGCGACT...`가 주어질 때, 입력은 2-mer로 나뉩니다. AT부터 시작해서 한 글자씩 슬라이딩하면서 TC, CG, GC... 순서로 k-mer가 생성됩니다. 각 k-mer의 위치는 해시 테이블에 저장되며, 이를 통해 특정 k-mer가 게놈 서열의 어느 위치에 나타나는지 빠르게 검색할 수 있습니다. 예를 들어 STR 구간에서 TAGA가 반복된다면, 해시 테이블에서 TAGA의 위치 목록을 조회하여 몇 번 반복되는지 파악할 수 있습니다. 또한 입력 게놈 서열 내 k-mer 분포 통계를 구할 때도 활용할 수 있습니다.

본 공격에서 victim enclave는 게놈 시퀀스 분석 전처리를 수행합니다. 오픈소스 k-mer 분석 도구인 **PRIMEX** 를 사용하였으며, 이 도구는 각 k-mer의 위치를 해시 테이블에 삽입합니다. 각 해시 테이블 엔트리는 해당 k-mer가 등장한 위치들을 저장하는 배열을 가리키는 포인터를 갖습니다.

### Attack Details
![s4](/assets/img/posts/papers/softgrand_4.png)

공격의 목표는 victim enclave가 입력 게놈 시퀀스를 전처리(인덱싱)하는 동안, STR 분석에 사용되는 13개 표준 위치에서의 microsatellite 반복 횟수(길이)를 캐시 모니터링을 통해 유출하는 것입니다. 공격자가 통제하는 환경에서 victim의 실행 시간이 결정론적이기 때문에, 캐시 모니터링 결과와 입력 시퀀스의 위치를 정확하게 대응시킬 수 있습니다. 

victim의 캐시 흔적은 위의 알고리즘이 나타내는 해시 테이블 삽입 연산과 연결될 수 있습니다. 그림에서 해시 테이블로의 삽입이 서로 다른 캐시 라인에 영향을 주고 있는 것을 알 수 있습니다. 