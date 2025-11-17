---
title: "Summary for Fuzzing the Latest NTFS in Linux with Papora: An Empirical Study"
date: 2025-11-18 01:28:16 +0900
categories: [Papers]
tags: []
---

# Summary for Fuzzing the Latest NTFS in Linux with Papora: An Empirical Study

# Index
- [1. Introduction](#introduction)
- [2. Background](#background)
- [3. Experimental Setup](#experimental-setup)
- [4. Experiment Results](#experiment-results)

# Introduction
NTFS는 Microsoft에서 개발한 Windows NT용 파일 시스템이다. 이후 수많은 하드디스크들이 NTFS 형식에 맞춰 출시되었고, 다른 운영체제들도 이에 맞춰 NTFS 지원을 개발해야했다. 그리고 리눅스의 **NTFS3** 도 그중 하나이다. 그러나 Linux Kernel의 NTFS3의 버그를 탐색하고 평가하는 도구가 아직 없었기에 **Papora** 라는 이름의 첫번째 NTFS3 퍼저를 개발하였다.

`Janus`나 `Hydra` 같은 파일 시스템 퍼저들도 여럿 있지만, NTFS 이미지로부터 **메타데이터를 추출** 하고 체크섬을 바로잡는 파서가 없거나, 파서가 있더라도 퍼즈 테스팅에 쓰기에 적합하지 않았다. 그리고 **KASAN** 을 지원하지 않아 취약점 탐색의 효율이 떨어졌었다.

1. NTFS의 구현은 오픈 소스가 아니기 때문에 쓸만한 이미지 파서를 만들기 쉽지 않다. 연구진은 여러 서드파티 릴리즈와 해당 문서들을 직접 비교하고, 어떤 구현이 예상되는 동작과 일치하는지 상호 참조하였다.
2. LKL을 활용하여 NTFS 이미지를 다루는 리눅스 커널의 동작을 에뮬레이션 하였다. 그러나 기존 LKL은 최신화가 잘 되지 않고, KASAN 역시 통합되어 있지 않았기 때문에 먼저 최신 버전으로 포팅을 한 후 LKL의 메모리 서브 시스템을 수정하여 **KASAN** 을 활성화 하였다. LKL은 선형 메모리 구조 같은 특수한 아키텍처에서 작동하는데, KASAN이 no-MMU LKL과 호환될 수 있도록 리팩토링하였다. 

3개의 0-day 취약점과 9개의 심각한 버그를 찾아냄으로서 Papora가 충분히 효과적인 퍼저임을 증명하였고, Linux의 NTFS가 여전히 OOB read나 null-pointer dereference 버그에 시달리고 있음을 알아냈다. 

# Background
## A. NTFS File System
파일 시스템은 `파일, 폴더, 링크, 데이터`에 대한 읽기/쓰기 작업을 효율적으로 처리할 수 있게 해주는 운영 체제의 핵심 요소이다. 1993년 Microsoft가 개발한 `New Technology File System(NTFS)`가 Windows NT의 첫번째 릴리즈와 함께 출시된 후 Linux에서 Windows 하드 드라이버에 접근하기 위해 많은 NTFS 드라이버가 개발되었고, NTFS3 역시 2021년에 커널에 추가되었다. 

### 1) NTFS Features
`File Allocation Table (FAT)` 파일 시스템의 후속으로서 NTFS는 많은 측면, 특히 **신뢰성과 보안** 측면에서 FAT를 많이 앞선다. 

NTFS 파일 시스템의 신뢰성은 두 가지 측면에서 반영될 수 있는데, 다른 저널링 파일 시스템과 유사하게 NTFS는 예기치 않은 시스템 크래시를 처리하기 위해 파일 시스템의 **일관성** 을 보장하는 `로깅 및 체크포인트 메커니즘`을 사용한다. 다른 한편으로는 **클러스터 리매핑** 이라 불리는 복구 기술도 신뢰성에 도움을 준다. 클러스터 내에 위치한 불량 섹터가 읽기 작업에서 감지되면 NTFS는 해당 클러스터를 새로 할당된 클러스터로 리매핑하고 더 이상 사용되지 않을 불량 클러스터를 표시한다.

보안의 경우, NTFS는 사용자 및 그룹 단위로 파일이나 디렉터리에 대한 접근 권한을 부여할 수 있다. 또한 **Encrypting File System(EFS)** 는 사용자가 NTFS 볼륨의 파일을 암호화할 수 있도록 하여 개인 키 없이는 공격자가 볼륨의 어떤 파일도 복호화할 수 없도록 만든다. 

### 2) NTFS Physical Structure
![NTFS_layout](/assets/img/posts/papers/Papora_1.png) <br>
위 그림은 NTFS 이미지의 레이아웃을 보여준다. 

- **Partition Boot Sector(PBS)** 는 시스템 부트스트래핑을 위한 중요한 정보를 담고 있다. 그리고 Program Counter를 부트스트랩 코드로 수정하는 역할을 한다.
- **Master File Table (MFT)** 은 모든 파일과 디렉터리의 메타데이터를 보유하고 메타데이터 자체까지 포함한다. MFT의 무결성 보장을 위해 NTFS는 MFT와 정확히 같은 데이터를 유지하는 MFT 사본을 유지한다. MFT는 NTFS 메타데이터를 위한 여러 항목들로 구성되고, 각 항목들은 고정된 기능을 갖고 엄격한 syntax를 따른다. 가장 중요한 것은 MFT가 파일의 속성과 같이 파일을 검색하는 데 필요한 일부 메타 정보도 저장한다는 것이다. NTFS에서 각 파일은 하나 또는 여러 섹터로 구성된 클러스터에 저장되며, 파일 이름, 타임스탬프, 심지어 파일 데이터와 같은 속성들의 목록으로 구조화된다. MFT에 포함되지 않은 파일 데이터는 파일 시스템 데이터에 저장된다. 

## B. Fuzzing
**Fuzzing** 이나 **fuzzy testing** 은 타겟 상태와 테스트 결과를 기반으로 변이된 입력을 타겟에 입력으로 넣는 소프트웨어 테스팅 기법이다. 많은 유명한 퍼저들은 **code coverage** 에 기반하여 입력 mutation을 유도한다. `AFL`이나 `libFuzzer` 같은 code coverage based 퍼저들은 컴파일 할 때 타겟에 계측 코드를 삽입하고, **input mutator** 에 타겟 상태를 다시 넣어 계속 새로운 상태를 탐색할 수 있도록 한다. 

User space program은 변이된 입력을 커맨드 라인이나 설정 파일 같은 형태로 넣어 반복 실행시키면 되지만 파일 시스템과 같은 OS component를 퍼징하는 것은 다른 문제이다. 파일 시스템의 경우 input space가 **two dimension** 이 되는데(파일 시스템 이미지, 일련의 system call), 기존 커널 퍼저(Trinity, Syzkaller)들이 효과적으로 만들어내기에는 파일 시스템 이미지는 다소 복잡하다. **Janus** 나 **Hydra** 같은 파일 시스템 퍼저는 커다란 이미지에서 메타데이터를 추출해내는 파일 시스템 전용 파서로 이 문제를 해결한다. 그리고 LKL을 활용하여 **clean-state OS** 를 유지할 수 있도록 한다.

# Experimental Setup
이 섹션은 어떻게 NTFS 퍼저를 구현하였고, NTFS 파일 이미지를 효율적으로 퍼징하는 방법을 설명한다.

## A. Challenges
- **C1,Disk Image**: 대부분의 mainstream 퍼저가 선호하는 입력의 크기는 1KB 미만이나, 파일 시스템 디스크 이미지는 보통 몇 메가바이트 단위부터 시작된다. 이를 통째로 변이시키거나 로드시키는 작업은 I/O에 큰 부담을 주며 퍼징 효율을 급감시킬 것이다.
- **C2, Context-aware File Operations**: 파일 연산 작업은 디스크 이미지와 별개의 귀중한 시드이다. 즉, 일련의 file operation도 시스템 크래시로 이어질 수 있는데, 이러한 연산들은 이미지에 대한 **context-aware 작업** 에 해당한다. 이러한 작업들은 탐색 공간을 지수적으로 증가시킬 뿐만 아니라 적절한 이미지 상태(예를 들어 MFT의 entry) 업데이트도 필요로 한다.
- **C3, Reproduction**: 운영체제를 대상으로 하는 전통적인 퍼저는 가상 환경을 주로 사용하는데, 이를 빈번하게 껐다 키면 시간이 너무 오래 걸려 보통 파일 시스템을 재사용한다. 이는 비결정적 상태로 이어지며 버그 탐색에도 큰 방해가 된다.

## B. Overview
![papora_workflow](/assets/img/posts/papers/Papora_2.png) <br>

위 그림은 Papora의 전반적인 흐름을 담고 있다. 먼저 NTFS 파서가 주어진 이미지를 스캔한 다음에 `corpus`를 만들어 Papora로 전송한다. 퍼저는 
1. 주어진 이미지의 메타데이터와 
2. file operations로 구성된 프로그램

을 둘다 변이시키고, 이에 맞춰 **status field** 를 업데이트 한다(단계 2,3). 그런 다음 NTFS 파서는 업데이트된 corpus를 온전한 변형된 이미지로 조립한다(단계 4). 이 이미지는 LKL에 의해 마운트되고 프로그램에 따라 실행된다(단계 5). 마지막으로 실행 결과가 출력된 다음 피드백 정보가 다시 전송되어 후속 mutation을 유도한다(단계 7).

## C. Corpus Building
위에서 볼 수 있듯이 corpus는 세 부분으로 구성된다.

- 주어진 이미지에서 추출된 메타데이터
- 일련의 file operations로 구성된 프로그램
- 상태 파일(status file)

특별히 설계된 NTFS 파서가 메타데이터, 즉 **PBS와 MFT의 entry** 들을 추출하고 이를 대량의 데이터로 압축한다. 이런 방식을 사용하면 버그 탐색에 도움이 안 되는 99퍼 이상의 이미지 공간은 corpus에 포함되지 않는다. 

두 번째 부분의 경우 초기 프로그램은 file operation의 빈 시퀀스이다. 아까 파일과 디렉토리의 여러 속성들은 `MFT`에 저장된다고 했는데, 이미지 스캔 과정에서 이 속성들은 세 번째 부분인 상태 파일에 패키징되고 유지된다. Papora는 조립된 corpus를 입력으로 받아, 메타데이터나 file operation 중 하나를 변형하고, 이미지를 마운트, 프로그램을 실행, 버그 트리거 여부를 확인한다. 그렇지 않으면 **Input corpus** 의 해당 필드가 업데이트 되고 다음 라운드 퍼징을 위해 corpus가 Papora로 전송된다. 

## D. NTFS Parser
파서가 해야할 일은 크게 세가지로 나뉜다.

첫째, 파서는 모든 메타데이터를 추출하고 이를 대량의 데이터로 압축할 수 있다. 파일 시스템의 경우, 마운트 후 이미지 충돌은 오직 버그가 있는 메타데이터로만 발생하며, 이는 이미지 공간의 1% 미만을 차지한다. 이는 나머지 99% 공간을 변형하는 것이 무의미함을 의미한다. NTFS 이미지의 경우, 메타데이터는 주로 **파티션 부트 섹터(PBS)와 마스터 파일 테이블(MFT)** 의 필드들로 구성된다. 따라서 변형이 수행되는 PBS와 MFT의 메타데이터를 압축하는 것은 변형과 후속 퍼징 모두의 효율성을 증가시킬 뿐만 아니라, 손상된 메타데이터와 관련된 새로운 버그를 찾을 가능성도 증가시킨다.

둘째, 파서는 메타데이터를 변형한 후 체크섬을 자동으로 수정한다. NTFS를 포함한 파일 시스템들은 모두 메타데이터의 무결성과 사용성을 보장하기 위해 체크섬을 채택한다. 체크섬 리터럴과 실시간 계산된 체크섬 간의 불일치는 오류를 발생시킨다. 따라서 메타데이터를 변형한 후, 파서는 변형된 NTFS 파일 시스템이 **체크섬에 대한 정적 검증** 을 통과할 수 있도록 모든 해당 체크섬을 재계산한다. Papora는 PBD, MFT 두 데이터 구조에 대한 특정 체크섬 수정 기능을 가지고 있다. 구체적으로, PBS는 부트를 위한 중요한 정보를 담고 있다. 예를 들어, 그것의 두 번째 필드인 OEM ID는 "NTFS" 다음에 4개의 공백 문자가 오는 것으로 고정되어 있다. 이 필드가 Papora에 의해 실수로 변형되더라도, 파서는 변형이 부팅에 부정적인 영향을 미치지 않도록 원래 값을 복원한다. 또한, MFT는 모든 파일과 디렉터리의 메타데이터를 저장한다. 각 파일 레코드의 헤더는 **업데이트 시퀀스 번호(USN)와 버퍼** 를 포함한다. NTFS는 레코드의 각 섹터의 마지막 두 바이트가 버퍼에 복사되고 USN이 그 자리에 기록되도록 요구한다. 부팅 후, NTFS는 헤더의 USN과 각 섹터의 마지막 두 바이트를 비교한다. 이를 위해, Papora가 MFT의 헤더를 변형하면, 정상성 검사를 통과하기 위해 해당 필드를 수정한다.

셋째, 퍼징 과정은 여전히 온전한 이미지에서 수행되므로, 파서는 또한 코퍼스의 변형된 메타데이터를 이미지에 다시 매핑하는 작업도 져야 한다. 이러한 목표를 달성하기 위해, 추출하는 동안 파서는 각 메타데이터 조각의 오프셋이 유지되는 비트맵을 유지한다. 비트맵을 기반으로, 변형된 메타데이터는 원래 슬롯으로 다시 채워질 수 있다.

NTFS-3G와 같은 전통적이고 잘 유지되는 NTFS 파서들도 NTFS 이미지를 파싱하고 로드할 수 있지만, 그들은 오직 주어진 이미지가 유효한지만 검증하고 유효하지 않다면 이미지가 성공적으로 로드되지 않는다. 하지만 위에서 언급했듯이, 파서는 체크섬을 수정하고 후속 과정을 위한 코퍼스를 조립하는 작업까지 해야 한다. 다시 말해, 우리의 파서는 유효성을 검증하는 것을 기반으로 추가적인 수정 과정을 수행한다. 또한, NTFS-3G는 퍼징 분석에 있어 너무 무겁고 비효율적이다. 요약하면, Papora를 구현하는 데 있어 별도의 파서를 구현하는 것이 필요하다.

## E. Fuzzing Image
Papora는 corpus의 `metadata` 부분을 변형하기 위해 비트/바이트 플립, 산술 연산 등 다양한 전략을 적용한다. 이 전략들은 다음과 같이 정리될 수 있다.

- 임의 오프셋에서 비트를 플립하거나, 임의 오프셋에서 임의 엔디안으로 흥미로운 바이트/워드/더블워드 값을 설정
- 임의 바이트/워드/더블워드 오프셋에서 임의의 값을 무작위로 더하거나 빼기
- 임의 오프셋에서 임의 길이만큼 임의 청크 또는 임의 바이트로 바이트를 덮어쓰거나 제공된 경우 사용자 지정 토큰으로 덮어쓰기

메타데이터를 변형시킨 다음, 파서가 필요한 체크섬을 다시 계산한다. 

## F. Fuzzing File Operations
메타데이터를 변형하는 거 말고도 Papora는 corpus의 두번째 부분, **일련의 file operations로 구성된 프로그램** 도 변이시킨다. 
두 가지 전략, `mutation`과 `generation`을 사용한다.

### Mutation
시드 프로그램에서 하나의 파일 연산을 무작위로 고른 다음에 무작위 값 대신 휴리스틱 값으로 파라미터 중 일부를 대체한다. 앞서 언급했듯 이러한 파일 연산들은 **context-aware** 하다. 그렇기에 선택된 값들은 현재 이미지에 대해 의미를 가져야 한다. 예를 들어 선택된 작업이 `fsync()`라면, Papora는 **열려있는 파일 디스크립터** 중 하나를 선택할 것이다. 이러한 전략은 `경로와 확장 속성과 관련된 시스템 콜`을 변형시키는 데도 쓸 수 있다.

### Generation
Papora가 mutation만으로 커버리지를 늘릴 수 없다면 적절한 인자를 가진 새로운 file operation을 프로그램에 추가하여 시도할 것이다. 추가로 각 파일 연산의 잠재적인 부작용 역시 고려되어 **program context** 가 이에 맞춰 업데이트 된다. corpus의 status file 부분에 파일과 디렉토리의 생성과 삭제 같은 변화들이 기록된다.

## G. Linux Kernel Library (LKL)
최신 커널에서의 버그를 찾기 위해 LKL을 6.0으로 업그레이드 하였다. 게다가 여러번의 수정을 거쳐 **KASAN** 역시 통합시켜 잘못된 메모리 접근을 찾을 수 있도록 했다. 이 과정에서 어떤 인퍼테이스는 도입되거나 바뀌거나 사라졌는데, **copy_thread** 의 경우 인터페이스가 변경되어 로직의 정확성을 보장하기 위해 해당 함수를 다시 작성해야 했다. 게다가 업스트림에서는 헤더파일 재정렬도 자주 발생한다. 일부 구조체나 매크로 정의가 새로운 헤더로 이동할 수 있고, 이로 인해 LKL을 최신 커널로 포팅하는 고정에서 `merge conflicts`, `build error` 등으로 이어지게 된다. 다른 한편으로 **KASAN** 을 LKL에 통합시키는 것 역시 많은 노력을 필요로 했다. 이는 LKL이 **no-MMU 아키텍처** 로 간주될 수 있기 때문으로 선형 메모리 주소만을 지원하기에 `KASAN initialization flow`와 충돌했다. 이를 해결하기 위해 KASAN의 기능을 유지하면서 코드를 직접 수정해야 했다.

이렇게 포팅에 성공하기만 한다면 가상 머신을 사용하는 것보다 훨씬 많은 장점이 있다. 일단 재부팅 측면에서 훨씬 빠르고 가벼우며, 에이징 커널 문제가 존재하기 않기 때문에 버그 재현도 비교적 쉽다. LKL의 경우 컴퓨팅 자원을 훨씬 적게 요구하므로 퍼징 과정을 빠르게, 많이 확장할 수 있다. 

# Experiment Results
이 섹션에서는 Papora로 찾은 모든 버그를 나열한 다음, 각 버그의 원인을 분석한다. 

## A. Results
![papora_bugs](/assets/img/posts/papers/Papora_3.png) <br>
Papora는 8 코어 CPU와 16Gb 메모리의 VMware 가상머신에서 실행되었고, 실험은 3개월간 진행되었다. 그 결과 위와 같이 9개의 버그와 3개의 취약점을 발견할 수 있었다. 이 버그들을 두 타입으로 분류하였는데 **Type 1** 은 NTFS 이미지가 마운트되면 시스템 충돌이 발생하는 상황을 의미하고 **Type 2** 는 이미지를 마운트 한 다음, 시스템 콜들을 호출하는 것으로 트리거할 수 있는 시스템 충돌이다. 

### 1) Categorized by Bug Type
60퍼센트가 넘는 버그가 **out-of-bounds read** 였는데, 커널 릭이나 메모리 오염으로 이어질 수 있는 위험한 유형의 버그이다. **out-of-bounds write** 취약점을 exploit 하는 것으로 `task_struct`의 데이터를 수정하여 권한 상승으로 이어질 수도 있다. 

25퍼센트 정도의 버그는 **null-pointer dereference** 버그였다. 이 버그는 바로 시스템 크래시를 발생시키고 설정에 따라 재부팅이나 hang으로 이어지게 한다. 이러한 유형의 버그들은 DoS 공격으로 이어질 수 있다. 이 외에도 Papora는 두 개의 heap corruption 버그를 발견하였고, 이는 UAF exploit에 활용될 수 있는 버그이다. 

### 2) Categorized by Root Cause
버그 분석 결과 대부분은 사용자가 변경할 수 있는 데이터에 대한 **검증 과정** 부족이 원인이었다. 

예를 들어 위조된 `offset` 필드는 메타데이터를 캐시하기 위해 할당된 메모리 크기로 제한되지 않으면 OOB read로 이어질 수 있다. 게다가 `offset`이 다른 **number-of-entries** 필드에서 파생된 경우 `number-lf-entries X size-of-entry` 값이 충분히 클 때 오버플로우된 `offset`이 조작될 수 있다. 이러한 위조된 값은 경계값 검사를 우회할 수 있기에 사용자가 제어할 수 있는 데이터와 관련된 모든 산술 연산은 신중하게 이루어져야 한다. 

Papora는 **type confusion** 버그들도 식별하였는데 본지는 **inode** 의 설계에서 비롯하는 Linux 파일 시스템의 흔한 버그라고 판단하고 있다. 각 **inode** 는 상태나 플래그에 따라 다양한 방식으로 해석될 수 있다. 아래 코드는 `ntfs_inode` 구조체이다.
```
union {
    struct ntfs_index dir;
    struct {
        struct rw_semaphore run_lock;
        struct runs_tree run;
#ifdef CONFIG_NTFS3_LZX_XPRESS
        struct page *offs_page;
#endif
    } file;
}
```
위에서 볼 수 있듯이 `ntfs_inode` 구조체의 union은 각 `ntfs_inode`가 dir 또는 file 중 하나를 나타내도록 한다. 커밋 467333a는 NTFS3 구현이 MFT_REC_MFT 파일을 디렉터리로 잘못 해석하고 유효하지 않은 포인터를 kfree() 하여 힙을 손상시키는 사례를 보여준다. 그리고 Papora가 식별한 `c1ca8ef` 버그의 경우 **Always-Incorrect Control Flow Implementation** 유형으로 분류될 수 있는데 다시 말해 악의적인 입력을 준비하는 대신, 악의적인 행위자가 불완전한 테스트 커버리지로 인해 놓친 정상적인 테스트 케이스로 충돌을 유발할 수 있다.

## B. Case Study on Type I
![ntfs_mount](/assets/img/posts/papers/Papora_4.png) <br>
타입 I 버그는 NTFS 디스크를 마운트하는 동안 발생하며, 위 그림에서 그 과정을 확인할 수 있다. 마운트를 호출하면 Linux 시스템은 커널 공간으로 트랩되는데, 마운트 프로세스의 대부분은 **VFS 레이어** 에 의해 처리된다. Linux의 파일들은 트리와 같은 계층 구조로 배열되어 있기 때문에 `vfs_get_tree`는 마운트 가능한 루트를 얻기 위해 특화된 `ntfs_fs_get_tree` 를 호출한다. 

NTFS 구현 내에서 **ntfs_fill_super** 함수가 중요한 역할을 하는데, 구체적으로는 **Partition Boot Sector** 를 파싱하고 클러스터 크기와 일반 파일의 최대 크기와 같은 매개변수 데이터를 읽는다. 또한 **Master File Table** 에서 모든 메타데이터 파일을 로드한다. 마지막으로, 디스크에서 NTFS 파일 시스템의 루트 디렉터리를 읽는다. 이 모든 로드된 데이터는 수퍼블록 구조인 `ntfs_sb_info`에 채워진다. 

이 섹션에서는 새 개의 대표적인 타입 I 버그에 대한 케이스 스터디를 진행한다. 근본 원인은 다 다르지만 이미지가 마운트되면 시스템 크래시가 발생한다.

### 1) 0b66046
이 버그는 구현 오류에서 기인한 `null pointer dereference`에서 발생한다. 이전에 설명했듯이 `ntfs_fill_super`의 첫번째 과정은 Partition parse boot를 파싱하는 것인데, **ntfs_init_from_boot** 라는 함수에 구현되어 있고, 아래는 그 코드이다. 
```
static int ntfs_init_from_boot(struct super_block
    * sb, u32 sector_size, u64 dev_size) {
    // some operations
    sbi -> record_size = record_size = boot ->
        record_size < 0 ?
    1 << (-boot -> record_size) :
    (u32) boot -> record_size << sbi -> cluster_bits;

    if (record_size > MAXIMUM_BYTES_PER_MFT)
        goto out;

    sbi -> record_bits = blksize_bits(record_size);
    // some operations
}

    /* assumes size > 256 */
static inline unsigned int blksize_bits(unsigned
    int size) {
    unsigned int bits = 8;
    do {
        bits++;
        size >>= 1;
    } while (size > 256);
    return bits;
}
```
일단 여기까지..
