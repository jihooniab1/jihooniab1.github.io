---
title: "KNighter: Transforming Static Analysis withLLM-Synthesized Checkers"
date: 2026-05-12 00:00:00 +0900
categories: [Papers]
tags: [security, LLM]
permalink: /posts/knighter/
math: true
---

## Summary for KNighter: Transforming Static Analysis withLLM-Synthesized Checkers

## Introduction
커널과 같은 기반 소프트웨어의 신뢰성은 결함을 잡아내는 방법론에 크게 좌우되는데, 그중 **정적 분석(static analysis)** 은 코드를 실행하지 않고 소스코드를 검사할 수 있어, 하드웨어 의존적 드라이버나 복잡하고 거의 실행되지 않는 경로, 실제 환경에서 재현하기 어려운 설정 등을 분석하는 데 특히 유용합니다. <br>
![k_1](/assets/img/posts/papers/knighter_1.png) <br>

위 그림에서 확인할 수 있듯이, 대규모 시스템의 정적 분석에는 두 가지 과제가 있습니다: 다양한 버그 패턴을 다루는 것과 거대한 코드베이스를 처리하는 것입니다. 이상적인 정적 분석기는 i) 시스템 고유의 세밀한 시멘틱 관련 결함을 포함해 광범위한 버그를 탐지하고, ii) 수백만 줄의 소스코드를 효율적으로 처리해야 합니다. 그러나 기존 방법들은 이 두 목표 중 하나를 희생하는 경향이 있습니다.

**전통적 정적 분석** 은 사전 정의된 규칙 기반 검사에 의존하므로 도메인 전문 지식과 상당한 엔지니어링 노력이 필요하며, 결과적으로 좁은 범위의 버그 패턴에만 대응할 수 있습니다. 반면 **LLM 기반 정적 분석** 은 과거 패치 커밋에서 직접 버그 패턴을 학습할 수 있지만, 제한된 컨텍스트 윈도우와 높은 연산 비용, 그리고 환각(hallucination) 문제로 인해 대규모 시스템에 직접 적용하기 어렵습니다.

본 논문에서는 LLM으로 코드베이스 전체를 직접 분석하는 대신, **LLM을 이용하여 static checker를 합성** 하는 방식을 제안합니다. LLM은 이전 패치들로부터 버그 패턴을 학습하고, 학습된 패턴은 독립적으로 실행 가능한 정적 체커로 인코딩됩니다. 이를 통해 LLM의 시멘틱 이해 능력은 체커 생성 시점에만 활용하고, 실제 코드베이스 스캔은 합성된 체커가 결정론적으로 수행하므로 컨텍스트 길이와 비용 문제를 동시에 해결합니다. 환각(hallucination) 문제 역시 구조적으로 대응하는데, 합성된 체커를 원본 패치 이전 코드에 실행하여 해당 버그를 실제로 탐지하는지 ground truth로 검증함으로써, LLM이 만들어낸 규칙이 실제 버그 패턴과 정확히 대응되는지 확인할 수 있습니다.

그러나 완전한 정적 분석 로직을 한 번에 합성하는 것은 상당한 난이도를 갖기 때문에, 본 논문에서는 **multi-stage synthesis pipeline** 을 구성하여 체커 생성을 단계별로 분할하고, **fully automated refinement pipeline** 을 통해 체커의 품질을 반복적으로 향상시키며 false positive를 줄입니다.

이러한 방법론을 적용하여 만든 **KNighter** 는 `Clang Static Analyzer(CSA)` 를 기반으로 리눅스 커널을 대상으로 합니다. KNighter는 평균 4.3년간 잠복해 있던 92개의 새로운 버그를 발견하였으며, 이 중 77개가 확인되고 57개가 수정되었고, 30개의 CVE를 발급받았습니다.

## Background and Motivation
### Clang Static Analyzer
Clang Static Analyzer(CSA)는 C/C++/Objective-C를 대상으로 하는 정적 분석 엔진으로, 내부적으로 `ExplodedGraph`를 구축하여 **path-sensitive symbolic execution** 을 수행합니다. ExplodedGraph의 각 노드는 프로그램의 특정 지점(ProgramPoint)과 그 시점의 추상 상태(ProgramState)의 쌍으로 구성되며, 분기마다 경로가 독립적으로 탐색됩니다.

CSA의 핵심 설계는 **분석 엔진과 탐지 로직의 분리** 에 있습니다. 경로 탐색, 기호 실행, 메모리 모델링은 엔진이 담당하고, 개별 버그 패턴의 탐지는 **체커(checker)** 라는 독립된 플러그인이 담당합니다. 체커는 함수 호출 전후, dead symbol 식별, 포인터 탈출 등 특정 분석 이벤트에 대한 콜백을 등록하는 이벤트 기반 구조로, 새로운 버그 패턴을 추가할 때 엔진 자체를 수정할 필요 없이 체커만 작성하면 됩니다. 체커 개발은 i) 탐지할 버그 패턴 정의, ii) 해당 이벤트에 대한 콜백 구현, iii) 프레임워크에 체커 등록, iv) 테스팅 시스템 통합의 단계로 이루어집니다. <br>

![k_2](/assets/img/posts/papers/knighter_2.png) <br>

위의 예시 체커는 4개의 콜백 함수를 등록하고 있습니다. `checkPostCall` 콜백은 함수 호출 후에 활성화되며, `ExprHasName`을 이용하여 호출이 `devm_kzalloc`으로 이어지는지 확인하고, 맞다면 반환된 메모리 영역을 커스텀 상태 맵 `PossibleNullPtrMap`에 unchecked(`false`)로 기록합니다. `checkBranchCondition` 콜백은 분기 조건에서 해당 포인터에 대한 null 체크가 수행되는지를 감시합니다. `if (!ptr)` 형태의 부정 연산자 패턴과 `if (ptr == NULL)` 또는 `if (ptr != NULL)` 형태의 직접 비교 패턴을 인식하며, 이러한 조건이 확인되면 `markRegionChecked`를 호출하여 해당 메모리 영역의 상태를 checked로 갱신합니다. `checkLocation` 콜백은 메모리 위치에 대한 접근이 발생할 때 트리거되며, `PossibleNullPtrMap`에서 해당 영역이 여전히 unchecked 상태인지 조회합니다. unchecked 상태인 포인터가 역참조되고 있다면 `reportUncheckedDereference`를 통해 경고를 발생시킵니다. 마지막으로 `checkBind` 콜백은 포인터 대입 연산을 처리합니다. `ptr_b = ptr_a`와 같은 대입이 일어나면 `PtrAliasMap`에 양방향으로 앨리어싱 관계를 기록하여, 원본 포인터가 다른 변수로 복사되더라도 null 체크 상태를 놓치지 않도록 추적을 유지합니다.

### Motivating Example
![k_3](/assets/img/posts/papers/knighter_3.png) <br>

위 패치는 `devm_kzalloc` 함수 호출 후 null 포인터 체크 누락으로 인한 Null-Pointer-Dereference 취약점을 수정하는 패치입니다. Smatch와 같은 커널 특화 체커를 포함한 기존 정적 분석 도구들은 `devm_kzalloc`이 실패 시 NULL을 반환할 수 있다는 도메인 지식이 없어 이 유형의 버그를 탐지하지 못했습니다. KNighter는 이 패치로부터 **devm_kzalloc의 반환값이 NULL인지 확인하지 않으면 Null-Pointer-Dereference로 이어질 수 있다는 핵심 패턴** 을 추출하고, 합성된 체커는 실행 경로를 따라가며 null 체크 여부를 추적하고 포인터 앨리어싱까지 처리합니다. 이 체커를 통해 리눅스 커널에서 3개의 새로운 취약점을 발견했으며, 그중 하나는 CVE-2024-50103으로 지정되었습니다.

LLM을 이용하여 커널을 직접 스캐닝하는건 굉장히 비싼 작업이 될 수 있지만, KNighter 정적 분석은 LLM을 반복해서 호출하는 것보다 훨씬 자원 소모가 덜하다고 볼 수 있습니다. LLM을 이용하여 효과적인 체커를 생성하기 위해 여러 단계로 이뤄진 파이프라인을 구성하여 체커를 생성하고, 패치 기록과 비교하여 실제로 유의미한 체커가 만들어진게 맞는지 확인합니다.

## Design
KNighter는 패치 커밋을 입력으로 받아 대응되는 CSA 체커를 반환합니다. `Valid Checker`는 버그가 있는 코드와 패치된 코드를 올바르게 구별하고, 패치 전 코드를 결함 상태로 판단하고 패치된 코드를 올바르다고 판단합니다. `Plausible checker`는 valid checker 중에서도 실용적 가치(낮은 오탐률, 리포트 수)까지 갖춘 체커를 의미합니다. <br>

![k_4](/assets/img/posts/papers/knighter_4.png) <br>

KNighter는 위 그림에 나와 있는 것처럼 에이전틱 워크플로우를 활용하여 패치 커밋으로부터 정적 분석기를 합성합니다. 크게 `Checker Synthesis`와 `Checker Refinement` 두 단계로 나뉩니다. 합성 단계에서는 입력 패치를 분석하여 버그 패턴을 식별하고, 탐지 계획을 수립한 뒤 CSA 체커를 구현합니다. 컴파일 에러가 발생하면 syntax-repair 에이전트가 컴파일러 에러 메시지를 기반으로 자동 수정합니다. 이 과정을 통해 `valid checker`가 생성되면 정제 단계로 넘어갑니다. 정제 단계에서는 valid checker로 전체 커널을 스캔하여 버그 리포트를 생성하고, triage agent가 각 리포트의 오탐 여부를 판별합니다. 오탐으로 식별된 케이스는 refinement agent에 피드백되어 체커 로직을 반복적으로 개선합니다. 최종적으로 낮은 오탐률을 보이거나 일정 수 이하의 리포트만 생성하는 체커를 **plausible checker** 로 분류합니다.

### Checker Synthesis
![k_5](/assets/img/posts/papers/knighter_5.png) <br>

위 알고리즘은 multi-stage 체커 합성 파이프라인을 나타냅니다. 버그 패턴 분석, 합성 계획 수립, 체커 구현, 문법 수정(5번까지), 체커 유효성 확인 단계로 이뤄집니다. 

#### Bug Pattern Analysis
  