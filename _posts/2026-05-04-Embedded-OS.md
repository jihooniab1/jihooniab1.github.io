---
title: "임베디드 OS 개발 프로젝트"
date: 2025-11-04 00:00:00 +0900
categories: [Books]
tags: [OS]
permalink: /posts/Embedded-OS/
---
## 1장
**임베디드 운영체제:** 하드웨어에 내장되어 있는 운영체제. 운영체제의 기능 중 필요한 것만 효율적으로 구현

**RTOS(RealTime Operating System):** 운영체제의 응답과 동작이 즉각적이고 실시간으로 이뤄짐. 에뮬레이터 환경을 갖고 개발할 예정

https://github.com/navilera/Navilos << 교재에서 작성된 코드가 있는 아카이브

```sh
wget https://github.com/navilera/Navilos/archive/95f2b8d.zip
```
각 챕터 커밋의 고유값을 바꿔가며 코드를 다운받을 수 있음.

## 2장
임베디드 시스템에서 동작하는 펌웨어를 만들려면, 해당 임베디드 시스템에 맞는 컴파일러를 사용해야함. ARM이면 ARM 컴파일러, MIPS는 MIPS용.. 컴파일하는 환경과 결과물이 실행될 환경이 다를 때 **크로스 컴파일러(cross-compiler)** 를 사용함. arm을 지원하는 GCC에도 여러가지가 있는데 `gcc-arm-플랫폼-ABI 타입` 형태로 구성되어 있음. 플랫폼이 linux면 linux용 실행 파일을 만들고, none이면 ARM 바이너리를 생성하는 것. **ABI(Application Binary Interface)** 는 C 언어에서 함수 호출을 어떻게 하는지를 정한 규약으로, 교재에서는 `gcc-arm-none-eabi`를 사용함
```sh
sudo apt install gcc-arm-none-eabi

user@ubuntu-AI:~$ arm-none-eabi-gcc -v
Using built-in specs.
COLLECT_GCC=arm-none-eabi-gcc
COLLECT_LTO_WRAPPER=/usr/lib/gcc/arm-none-eabi/13.2.1/lto-wrapper
Target: arm-none-eabi
...
```

에뮬레이터로는 `qemu-system-arm`을 사용. 지원하는 머신 목록도 확인할 수 있음.
```sh
sudo apt install qemu-system-arm

user@ubuntu-AI:~$ qemu-system-arm --version
QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.16)
Copyright (c) 2003-2023 Fabrice Bellard and the QEMU Project developers

user@ubuntu-AI:~$ qemu-system-arm -M ?
Supported machines are:
akita                Sharp SL-C1000 (Akita) PDA (PXA270)
ast1030-evb          Aspeed AST1030 MiniBMC (Cortex-M4)
ast2500-evb          Aspeed AST2500 EVB (ARM1176)
ast2600-evb          Aspeed AST2600 EVB (Cortex-A7)
bletchley-bmc        Facebook Bletchley BMC (Cortex-A7)
borzoi               Sharp SL-C3100 (Borzoi) PDA (PXA270)
bpim2u               Bananapi M2U (Cortex-A7)
canon-a1100          Canon PowerShot A1100 IS (ARM946)
cheetah              Palm Tungsten|E aka. Cheetah PDA (OMAP310)
collie               Sharp SL-5500 (Collie) PDA (SA-1110)
connex               Gumstix Connex (PXA255)
cubieboard           cubietech cubieboard (Cortex-A8)
emcraft-sf2          SmartFusion2 SOM kit from Emcraft (M2S010)
fby35-bmc            Facebook fby35 BMC (Cortex-A7)
fby35                Meta Platforms fby35
fp5280g2-bmc         Inspur FP5280G2 BMC (ARM1176)
fuji-bmc             Facebook Fuji BMC (Cortex-A7)
...
```

## 3장
ARM 코어에 전원이 들어오면 가장 먼저 하는 일 >> **리셋 벡터(reset vector, 0x00000000 주소)** 에서 32비트를 읽어서 그 명령을 실행 >> 메모리 주소 0x00000000에 명령어를 넣자! 

`boot` 디렉터리를 만들어줍니다.
```sh
user@ubuntu-AI:~/jihooniab1.github.io/code/embedded-os/chap03$ tree
└── boot
```

`Entry.S`를 살펴보겠습니다. **.text** 는 **.end** 가 나올 때까지의 모든 코드가 `text 섹션`이라는 의미입니다. GCC와 같은 컴파일러로 오브젝트 파일을 만들고 링커로 라이브러리를 링킹하면 결과물로 **실행 파일** 이 나옵니다. 이 파일들은 대부분 `ELF(Executable and Linkable Format)` 형식으로 만들어집니다. ELF는 헤더와 섹션으로 나뉘는데, 섹션에는 **.text, .rdata, .data, .bss, .symtab, .rel.text,. .rel.data, .debug, .line, .strtab** 등이 있습니다. `.text`는 컴파일러가 만든 기계어가 위치하고, `.symtab`은 전역 변수와 함수의 심볼을 저장하는 심볼 테이블입니다. 
```
.text
	.code 32

	.global vector_start
	.global vector_end

	vector_start:
		MOV		R0, R1
	vector_end:
		.space 1024, 0
.end
```
두 번째 줄의 `.code 32`는 명령어의 크기가 32비트라는 뜻입니다. `.global`은 C 언어의 **extern** 과 같은 일을 하여 `vector_start`와 `vector_end`의 주소 정보를 외부 파일에서 읽을 수 있도록 합니다. 7번째 줄은 `vector_start`라는 레이블을 선언하고 있으며, 8 번째 줄의 `MOV R0, R1`은 R1의 값을 R0에 넣는 명령어입니다. `.space 1024, 0`은 해당 위치부터 1024 바이트를 0으로 채우는 명령어입니다. 위 어셈블리 코드는 다음과 같은 바이너리를 기대하며 작성된 코드입니다.

```
0000 0000     MOV R0, R1
0000 0004     00000000

...

0000 0400     00000000
```

Entry.S를 컴파일하는 방법은 다음과 같습니다. `arm-none-eabi-as`는 어셈블리어 소스 파일을 컴파일합니다. **RealViewPB** 가 사용하는 ARM 코어가 `cortex-a8`이라 아키텍처는 armv7-a로, cpu는 cortex-a8로 설정합니다. 
```sh
user@ubuntu-AI:~/jihooniab1.github.io/code/embedded-os/chap03/boot$ arm-none-eabi-as -march=armv7-a -mcpu=cortex-a8 -o Entry.o ./Entry.S
user@ubuntu-AI:~/jihooniab1.github.io/code/embedded-os/chap03/boot$ arm-none-eabi-objcopy -O binary Entry.o Entry.bin
user@ubuntu-AI:~/jihooniab1.github.io/code/embedded-os/chap03/boot$ hexdump Entry.bin
0000000 0001 e1a0 0000 0000 0000 0000 0000 0000
0000010 0000 0000 0000 0000 0000 0000 0000 0000
*
0000400 0000 0000                              
0000404
```