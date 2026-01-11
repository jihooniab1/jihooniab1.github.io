---
title: "디바이스 매퍼 공부"
date: 2025-12-26 00:00:00 +0900
categories: [Study]
tags: [linux]
permalink: /posts/Device-Mapper-analysis/
math: true
---

리눅스의 디바이스 매퍼에 대해 공부하고 정리해보고자 합니다. LKL을 활용하여 퍼징 타겟으로 정할 수도 있는지 알아보는 것이 목표입니다.

# Red Hat Document
https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/logical_volume_manager_administration/device_mapper

## 개요

디바이스 매퍼: **볼륨 관리**를 위한 프레임워크를 제공하는 커널 드라이버. 매핑된 디바이스를 만드는 generic한 방법을 제공하고, 이는 논리 볼륨으로 사용될 수 있습니다. 볼륨 그룹이나 메타데이터 포맷에 대한 구체적인 정보는 모릅니다.

디바이스 매퍼는 다음과 같이 여러 상위 기술의 기반이 됩니다:
- LVM (Logical Volume Manager)
- Device-Mapper multipath
- dmraid

인터페이스의 경우 애플리케이션이 커널로 보낼 때는 **ioctl** 을, user가 커널로 보낼 때는 **dmsetup** 명령어를 사용합니다. LVM 논리 볼륨이 활성화될 때는 디바이스 매퍼가 사용이 되는데, 각 논리 볼륨은 **mapped device** 로 변환이 됩니다. 디바이스 매퍼는 linear, striped와 같은 다양한 **mapping target** 을 지원합니다. 한 쌍의 linear mapping으로 두 디스크를 하나의 논리 볼륨으로 붙일 수도 있습니다. LVM이 볼륨을 만들면, 그 기저에 **device-mapper device** 를 만들어서 `dmsetup` 커맨드로 쿼리가 될 수 있게 합니다.

## 매핑 테이블 (Device Table Mappings)

매핑된 디바이스는 테이블로 정의됩니다. 매핑된 장치를 위한 테이블은 줄 목록으로 구성되는데, 각 줄의 형식은 다음과 같습니다:

```
start length mapping [mapping_parameters...]
```
- `start`: Device Mapper 테이블의 첫 번째 줄에서 `start` 매개변수는 반드시 0이여야 합니다.
- `length`: 한 줄의 `start + length` 매개변수의 합은 바로 다음 줄의 `start` 값과 같아야 합니다.
- `mapping`: 매핑 테이블의 한 줄에 어떤 `mapping_parameters`가 지정되는지는 해당 줄에 지정된 mapping 유형에 따라 달라집니다. 
- Device Mapper의 크기는 항상 섹터(512 byte) 단위로 지정이 됩니다.

디바이스 매퍼에서 장치를 매핑 매개변수로 지정할 때, `/dev/hda` 같은 파일 시스템의 장치 이름으로 참조하거나, **major:minor** 형식의 번호로 참조할 수 있습니다. 후자가 pathname lookup 과정을 피할 수 있어서 더 선호됩니다.

다음 예시는 장치에 대한 매핑 테이블의 예시를 보여주고 있습니다. 테이블에 4개의 linear target이 있습니다. 각 줄의 처음 2개의 파라미터는 **segment starting block** 과 **length of the segment** 입니다. 그 다음은 매핑 타겟의 키워드고, 나머지는 `linear` 타겟에 대한 인자들입니다. 
```
0 35258368 linear 8:48 65920
35258368 35258368 linear 8:32 65920
70516736 17694720 linear 8:16 17694976
88211456 17694720 linear 8:16 256
```

# Device-Mapper deep dive
https://xuechendi.github.io/2013/11/14/device-mapper-deep-dive 이 블로그의 글(커널 3.6.3 기준)을 읽어보면서 정리하고, 최신 커널에 맞춰서 보완을 해보고자 합니다. 

아래 그림은 스토리지 서브시스템을 간단하게 나타낸 그림입니다. <br>

