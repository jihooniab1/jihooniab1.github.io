---
title: "임베디드 OS 개발 프로젝트"
date: 2026-05-04 00:00:00 +0900
categories: [Books]
tags: [OS]
permalink: /posts/Embedded-OS/
---
## 1장
**임베디드 운영체제:** 하드웨어에 내장되어 있는 운영체제. 운영체제의 기능 중 필요한 것만 효율적으로 구현한 것입니다.

**RTOS(RealTime Operating System):** 운영체제의 응답과 동작이 즉각적이고 실시간으로 이뤄집니다. 에뮬레이터 환경을 갖고 개발할 예정입니다.

https://github.com/navilera/Navilos << 교재에서 작성된 코드가 있는 아카이브입니다

```sh
wget https://github.com/navilera/Navilos/archive/95f2b8d.zip
```
각 챕터 커밋의 고유값을 바꿔가며 코드를 다운받을 수 있습니다.

## 2장
임베디드 시스템에서 동작하는 펌웨어를 만들려면, 해당 임베디드 시스템에 맞는 컴파일러를 사용해야함. ARM이면 ARM 컴파일러, MIPS는 MIPS용.. 컴파일하는 환경과 결과물이 실행될 환경이 다를 때 **크로스 컴파일러(cross-compiler)** 를 사용합니다. arm을 지원하는 GCC에도 여러가지가 있는데 `gcc-arm-플랫폼-ABI 타입` 형태로 구성되어 있습니다. 플랫폼이 linux면 linux용 실행 파일을 만들고, none이면 ARM 바이너리를 생성하는 것. **ABI(Application Binary Interface)** 는 C 언어에서 함수 호출을 어떻게 하는지를 정한 규약으로, 교재에서는 `gcc-arm-none-eabi`를 사용합니다.
```sh
sudo apt install gcc-arm-none-eabi

user@ubuntu-AI:~$ arm-none-eabi-gcc -v
Using built-in specs.
COLLECT_GCC=arm-none-eabi-gcc
COLLECT_LTO_WRAPPER=/usr/lib/gcc/arm-none-eabi/13.2.1/lto-wrapper
Target: arm-none-eabi
...
```

에뮬레이터로는 `qemu-system-arm`을 사용. 지원하는 머신 목록도 확인할 수 있습니다. 
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
하드웨어에서 정보를 읽어오고 쓰는 작업을 하려면 특정 값을 저장하고 읽고 쓰는 공간인 **레지스터** 를 이용해야 합니다. 데이터시트는 해당 하드웨어가 가지고 있는 레지스터의 목록과 설명, 레지스터에 어떤 값을 썼을 때 하드웨어가 어떻게 동작하는지를 적어놓은 문서입니다. RealViewPB는 ARM 개발자 문서 홈페이지에서 데이터 시트를 찾아볼 수 있습니다. <br>

![ch3_1](/assets/img/posts/books/embedded/ch3_1.png) <br>

메모리 주소 0x10000000에 어떤 값이 있는지 데이터시트를 통해 찾아보겠습니다. **Programmer's Reference -> Status and system control registers -> ID Register,SYS_ID** 에서 0x10000000 주소에 있는 레지스터의 정보를 알아낼 수 있습니다. <br>

![ch3_2](/assets/img/posts/books/embedded/ch3_2.png) <br>

데이터시트에 따르면 SYS_ID는 `FPGA, ARCH, BUILD, HBI, REV` 항목으로 나뉘어져 있으며, 보드와 FPGA를 식별하는데 사용됩니다. SYS_ID로부터 메모리를 로드하여 HBI, ARCH 항목의 기본값이 실제로 로드되는지 확인해보겠습니다. Entry.S를 아래와 같이 수정하여 하드웨어 정보를 읽어오게 할 수 있습니다.
```
.text
	.code 32

	.global vector_start
	.global vector_end

	vector_start:
		LDR R0, =0x10000000
		LDR R1, [R0]
	vector_end:
		.space 1024, 0
.end
```

다시 빌드하고 실행한 후, gdb를 붙여보겠습니다. 참고로 컴파일할 때 `-g` 옵션을 넣어서 디버깅 심벌을 실행 파일에 포함할 수 있고, gdb 안에서 **file** 명령을 통해 심볼을 읽어올 수 있습니다. <br>

![ch3_3](/assets/img/posts/books/embedded/ch3_3.png) <br>

![ch3_4](/assets/img/posts/books/embedded/ch3_4.png) <br>

데이터시트가 설명하는 내용과 디버깅 결과가 일치하는 것을 볼 수 있습니다. 0x1780500이라는 값을 2진수로 변환한 후 항목에 맞게 나누면 `0000` `000101111000(178)` `0000` `0101(5)` `00000000` 이렇게 나눠지고, 보드 리비전과 버스 아키텍처 정보를 알아낼 수 있습니다. 

## 4장
### 메모리 설계
실행 파일은 메모리를 크게 세 가지로 나누어 text(코드가 있는 공간), data(초기화된 전역 변수), BSS(초기화되지 않은 전역 변수)로 나눕니다. 실제 환경에서는 메모리의 크기와 속도를 전부 고려하여 영역을 배치하지만 QEMU에서는 그런 구분이 없으니 순서대로 배치합니다. 

text 영역에는 1MB를 할당하고, **익셉션 벡터 테이블** 을 배치할 것이므로 시작 주소는 0x00000000이 되어야 합니다. 크기가 1MB이니 끝나는 주소는 0x000FFFFF입니다. 

UND, ABT, FIQ, IRQ, SVC, USR, SYS 개별 동작 모드마다 각 1MB씩 할당이 됩니다. USR, SYS 모드는 메모리 공간과 레지스터를 모두 공유하므로 하나로 묶어서 보았고 기본 동작 모드로 사용될 것이므로 2MB를 할당했습니다. 

RTOS 위에서 동작할 **태스크(task) 스택 영역** 은, 최대 `64개`의 태스크에 대해 1MB씩 할당하여 총 64MB를 할당합니다. 남는 공간은 동적 할당 메모리용으로 구분하였습니다.

| 영역 | 시작 주소 | 끝 주소 | 크기 |                                                                                                            
|------|-----------|---------|------|                                                                                                            
| 동적 할당 영역 | 0x04900000 | 0x07FFFFFF | 55MB |                                                                                              
| 전역 변수 영역 | 0x04800000 | 0x048FFFFF | 1MB |                                                                                               
| 태스크 스택 영역 | 0x00800000 | 0x047FFFFF | 64MB |
| UND 스택 영역 | 0x00100000 | 0x001FFFFF | 1MB |
| ABT 스택 영역 | 0x00200000 | 0x002FFFFF | 1MB |
| FIQ 스택 영역 | 0x00300000 | 0x003FFFFF | 1MB |
| IRQ 스택 영역 | 0x00400000 | 0x004FFFFF | 1MB |
| SVC 스택 영역 | 0x00500000 | 0x005FFFFF | 1MB |
| USR/SYS 스택 영역 | 0x00600000 | 0x007FFFFF | 2MB |
| Text 영역 | 0x00000000 | 0x000FFFFF | 1MB |

### 익셉션 벡터 테이블
이제 익셉션 테이블을 배치하고 핸들러를 작성할 차례입니다. ARM에서 전원이 켜지면 익셉션 벡터 테이블의 리셋 벡터를 읽고, 테이블이 배치되는 메모리 기본 주소는 보통 `0x00000000`입니다. 익셉션 벡터 테이블에는 7개의 익셉션이 있고, 테이블에 정의된 상황이 발생하면 PC에 핸들러 주소를 넣어 **익셉션 핸들러를 실행** 합니다. 구성은 다음과 같습니다.

| 오프셋 | 이름 | 설명 |
|-------|-----|-----|
| 0x00 | Reset | 전원이 켜지면 실행됨 |
| 0x04 | Undefined Instruction | 잘못된 명령어를 실행했을 때 |
| 0x08 | SVC(Supervisor Call) | SVC 명령으로 발생시키는 익셉션 |
| 0x0C | Prefetch Abort | 명령어 메모리에서 명령어를 읽다가 문제 발생 |
| 0x10 | DataAbort | 데이터 메모리에서 데이터를 읽다가 문제 발생 |
| 0x14 | Not used | 사용 안함 |
| 0x18 | IRQ Interrupt | IRQ 인터럽트가 발생했을 때 |
| 0x1C | FIQ Interrupt | FIQ 인터럽트가 발생했을 때 |

익셉션(exception)은 **CPU의 정상적인 실행 흐름을 끊고 미리 정해진 핸들러로 점프** 하게 만드는 모든 사건을 의미합니다. 프로그램 카운터는 보통 명령어 한 개의 크기만큼 증가하는데, 어떤 상황에서도 R0부터 R14까지의 레지스터 값은 context를 유지해야 합니다. 이를 위해서는 익셉션 핸들러를 처리한 후 원래 위치로 복구할 수 있어야 하고, 이를 위해서 ARM은 익셉션이 발생할 때 `R14(LR)`에 복귀할 주소를 자동으로 저장합니다. 예를 들어 USR 모드에서 프로그램이 수행되고 있다가 익셉션이 발생해서 IRQ 모드로 바뀌면 ARM은 자동으로 `R14_irq`에 다음에 실행할 명령어 위치(PC+4)를 저장합니다. 익셉션 핸들러가 끝나기 전에 다음 표에 있는 연산을 R14_x로 수행한 후에 PC에 그 값을 넣으면 다시 실행을 재개합니다. 

| 익셉션 | 복귀 주소 | 저장하는 값 |
|-------|---------|----------|
| SVC | MOVS PC, R14 svc | PC + 4 |
| SMC | MOVS PC, R14 mon | PC + 4 |
| UNDEF | MOVS PC, R14 und | PC + 4 |
| PABT | SUBS PC, R14 abt, #4 | PC + 4 |
| FIQ | SUBS PC, R14 q, #4 | PC + 4 |
| IR | QSUBS PC, R14 irq, #4 | PC + 4 |
| DABT | SUBS PC, R14 abt, #8 | PC + 8 |
| RESET | - | - | - |
| BKPT | SUBS PC, R14 abt, #4 | PC + 4 |

익셉션이 발생하면 ARM은 다음 동작을 수행합니다.

1. ARM 모드일 때 `PC + 4`나 `PC + 8`을 R14_x에 저장합니다.
2. CPSR을 익셉션별 동작 모드에 연결된 `SPSR_x`에 저장합니다.
3. CPSR의 동작 모드 비트와 I, T 비트의 값을 각 익셉션과 동작 모드에 맞게 변경합니다.
4. SCTLR(System Control Register)의 EE 비트 값에 따라 E 비트를 설정합니다.
5. SCTLR의 TE 비트 값에 따라 T 비트를 설정합니다.
6. PC의 값을 익셉션 벡터 위치로 강제 변경합니다.

인터럽트는 프로그램의 흐름이 외부 요인으로 인해 중단되는 것을 뜻하며, **ARM에서는 익셉션과 인터럽트를 구분하지는 않습니다**. ARM에서는 VIC(Vectored Interrupt Controller) 혹은 GIC(Generic Interrupt Controller)라는 이름의 **인터럽트 소스를 받아서 CPU에 전달하는 중간 관리자** 를 이용하여 인터럽트를 관리합니다. 두 가지 인터럽트가 있는데 하나는 `FIQ`이고, 다른 하나는 `IRQ`입니다. 

IRQ는 **Interrupt Request** 의 약자로 FIQ보다 우선순위가 낮기에 IRQ와 FIQ가 동시에 발생하면 FIQ 처리 요청이 펌웨어에 먼저 보내집니다. `CPSR(Current PSR)`의 I 비트를 1로 설정하면 IRQ 익셉션을 비활성화하고, IRQ 요청이 펌웨어로 처리되지 않습니다. 

FIQ는 **Fast Interrupt Request** 의 약자로, 별도로 `R8`에서 `R12`까지의 레지스터를 가지고 있어 펌웨어에서 인터럽트 처리를 할 때 R8에서 R12까지만 사용하도록 코드를 작성하면 context swtiching overhead(레지스터 백업, 복구)를 줄일 수 있습니다.

NMFI는 **Non-Maskable Fast Interrupt** 의 약자로, 마스크할 수 없는 인터럽트를 의미합니다. 이걸 켜면 FIQ를 비활성화 할 수 없습니다. NMFI를 켜면 하드웨어가 자동으로 CPSR의 F 비트를 0으로 클리어하고, 이걸 켰을 때 CPSR의 F 비트가 1이 되는 경우는 FIQ 익셉션이 발생하거나 리셋 익셉션이 발동했을 경우 뿐입니다. 

LIL은 **Low Interrupt Latency** 의 약자로, 인터럽트 지연을 줄이기 위한 기능 중 하나입니다. LIL은 인터럽트가 발생하면 현재 실행 중인 명령이 아직 끝나지 않아도 취소하고 인터럽트를 먼저 처리한 다음, `SUBS PC, r14, #4`로 다시 그 명령어로 복귀하여 실행을 재개합니다.

Interrupt Controller는 인터럽트 처리를 전담하는 주변장치입니다. ARM에는 인터럽트를 감지하는 핀이 IRQ, FIQ 딱 두개로 인터럽트의 발생 여부 외에는 알 수 없습니다. 이를 위해 인터럽트 컨트롤러는 인터럽트가 발생했을 때 해당 인터럽트의 종류를 레지스터에 기록하고, 인터럽트 발생 시 IRQ 혹은 FIQ에 맞춰서 인터럽트 신호를 줍니다. 또한 특정 인터럽트를 마스킹할 수 있으며, 인터럽트 간 우선순위를 설정할 수 있습니다. **Interrupt Service Routine(ISR)** 은 인터럽트 핸들러의 하위 개념으로, 인터럽트 핸들러에서 인터럽트 컨트롤러의 값을 읽어 인터럽트 소스를 확인하고 해당하는 ISR로 진입하는 방식입니다.

**Abort** 역시 ARM에서는 익셉션의 한 종류로 정의됩니다.

```
.text
	.code 32

	.global vector_start
	.global vector_end

	vector_start:
		LDR		PC, reset_handler_addr
		LDR		PC, undef_handler_addr
		LDR		PC, svc_handler_addr
		LDR		PC, pftch_abt_handler_addr
		LDR		PC, data_abt_handler_addr
		B		.
		LDR		PC, irq_handler_addr
		LDR		PC, fiq_handler_addr

		reset_handler_addr: 	.word reset_handler
		undef_handler_addr: 	.word dummy_handler
		svc_handler_addr: 		.word dummy_handler
		pftch_abt_handler_addr: .word dummy_handler
		data_abt_handler_addr:  .word dummy_handler
		irq_handler_addr:		.word dummy_handler
		fiq_handler_addr:		.word dummy_handler
	vector_end:

	reset_handler:
		LDR		R0, =0x10000000
		LDR		R1, [R0]
	vector_end:
		.space 1024, 0

	dummy_handler:
		B .
.end
```
8~15 line에 익셉션 벡터 테이블이 작성되어 있습니다. 그 아래에는 벡터 테이블에서 사용하는 변수들이 선언되어 있습니다. 이전의 `SYS_ID`를 읽는 코드가 리셋 익셉션 핸들러에 들어있고, 실행 결과는 다음과 같습니다. <br>

![ch4_1](/assets/img/posts/books/embedded/ch4_1.png) <br>

