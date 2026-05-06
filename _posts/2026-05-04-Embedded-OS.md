---
title: "임베디드 OS 개발 프로젝트"
date: 2026-05-04 00:00:00 +0900
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
### 리셋 벡터
ARM 코어에 전원이 들어오면 가장 먼저 하는 일 >> **리셋 벡터(reset vector, 0x00000000 주소)** 에서 32비트를 읽어서 그 명령을 실행 >> 메모리 주소 0x00000000에 명령어를 넣자! 

`boot` 디렉터리를 만들어줍니다.
```sh
$ tree
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

Entry.S를 컴파일하는 방법은 다음과 같습니다. `arm-none-eabi-as`는 어셈블리어 소스 파일을 컴파일합니다. **RealViewPB(데이터시트를 구하기 쉬워 선택)** 가 사용하는 ARM 코어가 `cortex-a8`이라 아키텍처는 armv7-a로, cpu는 cortex-a8로 설정합니다. 컴파일에 성공하면 `Entry.o` 파일이 생성되는데, `arm-none-eabi-objcopy` 명령으로 바이너리만 뽑아낼 수 있습니다. hexdump 명령으로 추출한 바이너리를 확인하면 예측한 대로 바이너리가 생성되었음을 알 수 있습니다. 참고로 arm-none-eabi-as에서 `none`은 운영체제가 아니라 **베어메탈 환경** 을 타겟으로 한다는 의미이며, `eabi`는 ARM만의 **EABI(Embedded Application Binary Interface)** 규격을 의미합니다. 
```sh
$ arm-none-eabi-as -march=armv7-a -mcpu=cortex-a8 -o Entry.o ./Entry.S
$ arm-none-eabi-objcopy -O binary Entry.o Entry.bin
$ hexdump Entry.bin
0000000 0001 e1a0 0000 0000 0000 0000 0000 0000
0000010 0000 0000 0000 0000 0000 0000 0000 0000
*
0000400 0000 0000                              
0000404
```

### 실행 파일 만들기

QEMU가 펌웨어 파일을 읽어서 부팅하려면, 지정한 펌웨어 바이너리 파일이 `ELF 형식`이어야 합니다. ELF 파일을 만들려면 **링커(Linker)** 의 도움이 필요한데, 링커는 여러 오브젝트 파일을 묶어 하나의 실행 파일을 만드는 프로그램입니다. 링커가 동작하려면 `링커 스크립트`가 필요한데, 다음 코드는 간단하게 구현된 링커 스크립트 `navilos.ld`입니다. 펌웨어가 동작하는 하드웨어 환경에 맞게 **펌웨어의 섹션 배치를 조정** 해야 할 경우 링커 스크립트를 사용합니다.

1번째 줄의 `ENTRY` 지시어는 시작 위치의 심벌을 지정합니다. `SECTIONS`는 뒤의 블록이 **섹션 배치 설정 정보** 를 갖고 있음을 나타냅니다. `.=0x0;`은 첫 번째 섹션이 메모리 주소 0x00000000에 위치하는 것을 의미합니다. `.text`는 text 섹션의 배치 순서를 지정합니다. **메모리 주소 0x00000000에 리셋 벡터가 위치** 해야 하므로 `vector_start` 심벌이 먼저 나오고 이어서 .text 섹션을 적습니다. 이어서 data 섹션과 bss 섹션을 연속된 메모리에 배치합니다. 
```
ENTRY(vector_start)
SECTIONS
{
	. = 0x0;
	
	
	.text :
	{
		*(vector_start)
		*(.text .rodata)
	}
	.data :
	{
		*(.data)
	}
	.bss :
	{
		*(.bss)
	}
}
```

다음과 같이 링커로 실행 파일을 만들 수 있습니다. `-n`은 링커가 섹션의 정렬을 자동으로 맞추지 않도록 하는 옵션이고, `-T`는 링커 스크립트를 알려주는 옵션입니다. `-nostdlib` 명령은 자동으로 표준 라이브러리를 링킹하지 못하도록 지시합니다. 생성된 `navilos.axf` 파일을 **arm-none-eabi-objdump -D** 명령으로 디스어셈블하면 내부 메모리가 원하는 대로 구성되어있음을 확인할 수 있습니다. 기계어 자체는 `0xE1A00001`임도 확인할 수 있습니다.
```sh
$ arm-none-eabi-ld -n -T ./navilos.ld -nostdlib -o navilos.axf boot/Entry.o
$ arm-none-eabi-objdump -D navilos.axf

navilos.axf:     file format elf32-littlearm


Disassembly of section .text:

00000000 <vector_start>:
   0:	e1a00001 	mov	r0, r1

00000004 <vector_end>:
	...
```

생성된 실행 파일은 호스트에서 바로 실행할 수는 없고, QEMU를 이용하여 실행할 수 있습니다. 다만 지금 실행해봤자 화면에 아무것도 뜨지 않을 것이기 때문에 **gdb-multiarch** 를 이용하여 메모리를 확인하겠습니다. 아래 명령을 통해 QEMU가 동작하자마자 중지되도록 한 후, gdb 포트를 열 수 있습니다.
```sh
$ qemu-system-arm -M realview-pb-a8 -kernel navilos.axf -S -gdb tcp::1234
```

`target remote: 1234`로 원격 디버깅을 하면 펌웨어 바이너리가 의도대로 동작하는 것을 확인할 수 있습니다. 
```
gef> target remote: 1234
Remote debugging using : 1234
0x00000000 in vector_start ()

...
------------ code: arm:ARM (gdb-native) ----
 -> 0x0 0100a0e1          <NO_SYMBOL>   mov    r0, r1
```

### 빌드 자동화
navlios.axf 파일을 만들기 위해서는 매번 `arm-none-eabi-as`로 어셈블리를 컴파일하고 `arm-none-eabi-ld`로 링킹을 해야합니다. 어셈블리 파일이 추가되면 `arm-none-eabi-as`를 한번 더 하고 또 링킹을 해야합니다. Makefile을 만들어 빌드 과정을 자동화할 수 있습니다. `$(wildcard boot/*.S)` 이건 boot 폴더에 있는 모든 `.S` 파일 목록을 가져온다는 뜻이고, `$(patsubst boot/%.S, build/%.o, ...)`는 boot 디렉터리에서 확장자가 S인 파일 이름을 찾아서 **o로 바꾼 다음 디렉터리도 build로 바꿔 ASM_OBJS 변수에** 값으로 넣는다는 뜻입니다.
```
ARCH = armv7-a
MCPU = cortex-a8

CC = arm-none-eabi-gcc
AS = arm-none-eabi-as
LD = arm-none-eabi-ld
OC = arm-none-eabi-objcopy

LINKER_SCRIPT = ./navilos.ld

ASM_SRCS = $(wildcard boot/*.S)
ASM_OBJS = $(patsubst boot/%.S, build/%.o, $(ASM_SRCS))

navilos = build/navilos.axf
navilos_bin = build/navilos.bin

.PHONY: all clean run debug gdb

all: $(navilos)

clean:
	@rm -fr build
	
run: $(navilos)
	qemu-system-arm -M realview-pb-a8 -kernel $(navilos)
	
debug: $(navilos)
	qemu-system-arm -M realview-pb-a8 -kernel $(navilos) -S -gdb tcp::1234,ipv4
	
gdb:
	arm-none-eabi-gdb
	
$(navilos): $(ASM_OBJS) $(LINKER_SCRIPT)
	$(LD) -n -T $(LINKER_SCRIPT) -o $(navilos) $(ASM_OBJS)
	$(OC) -O binary $(navilos) $(navilos_bin)
	
build/%.o: boot/%.S
	mkdir -p $(shell dirname $@)
	$(AS) -march=$(ARCH) -mcpu=$(MCPU) -g -o $@ $<
```

### 데이터시트
하드웨어에서 정보를 읽어오고 쓰는 작업을 하려면 **레지스터** 를 이용해야 합니다. 데이터시트는 해당 하드웨어가 가지고 있는 레지스터의 목록과 설명, 레지스터에 어떤 값을 썼을 때 하드웨어가 어떻게 동작하는지를 적어놓은 문서입니다. RealViewPB는 ARM 개발자 문서 홈페이지에서 데이터 시트를 찾아볼 수 있습니다. <br>

![ch3_1](/assets/img/posts/books/embedded/ch3_1.png) <br>

메모리 주소 0x10000000에 어떤 값이 있는지 데이터시트를 통해 찾아보겠습니다. 