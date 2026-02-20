---
title: "Software Grand Exposure: SGX Cache Attacks Are Practical"
date: 2026-02-20 00:00:00 +0900
categories: [Papers]
tags: [security, side channel, TEE]
permalink: /posts/SGX-step/
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
