---
title: "EntryBleed: A Universal KASLR Bypass against KPTI on Linux"
date: 2026-01-29 00:00:00 +0900
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

본 연구에서는 물리 호스트와 하드웨어 가속된 VM 두 환경에서 모두 공격이 작동하는 것을 확인하였습니다. 