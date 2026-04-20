---
title: "Side Channel Practice_TDXDown"
date: 2026-04-13 00:00:00 +0900
categories: [Study]
tags: [security, side channel]
permalink: /posts/Side+Channel+Practice_2/
math: true
---

# 사이드 채널 실습 - TDXDown: Single-Stepping TD

## TDXDown
[Github](https://jihooniab1.github.io/posts/TDXdown/) 링크에 정리되어 있는 single-stepping 논문 공격을 실제로 수행해보는 포스트입니다. 연구실에서 제공하는 서버 환경은 다음과 같습니다.

```
ubuntu@ubuntu:/boot$ lscpu
Architecture:             x86_64
  CPU op-mode(s):         32-bit, 64-bit
  Address sizes:          45 bits physical, 48 bits virtual
  Byte Order:             Little Endian
CPU(s):                   64
  On-line CPU(s) list:    0-63
Vendor ID:                GenuineIntel
  Model name:             Intel(R) Xeon(R) 6710E
    CPU family:           6
    Model:                175
    Thread(s) per core:   1
    Core(s) per socket:   64
    Socket(s):            1
    Stepping:             3
    CPU(s) scaling MHz:   33%
    CPU max MHz:          2400.0000
    CPU min MHz:          800.0000
    BogoMIPS:             4800.00
...
```

아티팩트 코드는 [Zenodo](https://zenodo.org/records/12683611)에서 구할 수 있습니다. 

## 아티팩트 분석
```
user@Ubuntu:~/Downloads/tdxdown-paper-artifacts/tdxdown-paper-artifacts$ ls -l
total 16
drwxr-xr-x 2 user user 4096 Apr 28  2024 'bios screenshots'
-rw-rw-r-- 1 user user 2065 Apr 29  2024  README.md
drwxrwxr-x 5 user user 4096 Apr 27  2024  single-stepping
drwxrwxr-x 5 user user 4096 Apr 28  2024  stumble-stepping
```

본 포스팅에서는 **single-stepping** 공격 관련 코드들을 먼저 분석해보고자 합니다. 

### kernel-deb-src-packages
```
user@Ubuntu:~/Downloads/tdxdown-paper-artifacts/tdxdown-paper-artifacts/single-stepping/kernel-deb-src-packages$ ls -l
total 223284
-rw-rw-r-- 1 user user   5115693 Apr 27  2024 linux-intel-opt_6.5.0-1003.3.diff.gz
-rw-rw-r-- 1 user user      5086 Apr 27  2024 linux-intel-opt_6.5.0-1003.3.dsc
-rw-rw-r-- 1 user user 223513863 Apr 27  2024 linux-intel-opt_6.5.0.orig.tar.gz
```

먼저 `inux-intel-opt_6.5.0.orig.tar.gz` 파일은 바닐라 Linux 6.5.0 원본 소스 코드입니다. 그리고 `linux-intel-opt_6.5.0-1003.3.diff.gz`는 Intel이 바닐라 6.5.0 커널에 추가한 **TDX host 지원 패치 묶음** 을 나타내며, linux-intel-opt_6.5.0-1003.3.dsc는 이 Debian 소스 패키지의 메타데이터 파일입니다. 패키지 이름, 버전, 체크섬 등을 담고 있으며 dpkg-source -x 명령이 이 파일을 읽어서 orig.tar.gz와 diff.gz를 올바르게 조합합니다. 

`dpkg-source -x` 명령을 사용하면 내부적으로 .dsc 파일을 읽은 후 orig 파일을 풀어서 베이스 소스 트리를 만들고 그 위에 diff.gz 패치를 적용합니다. 

### 커널에 새롭게 추가된 코드들
#### include/linux/tdx_step_gate_desc.h
IDT를 직접 조작하기 위한 로우 레벨 타입 정의들을 담고 있습니다.
```c
/* IA-64: 16-byte gate (from Linux kernel arch/x86/include/asm/desc_defs.h) */
typedef struct {
    uint16_t offset_low;
    uint16_t segment;
    unsigned ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t zero1;
} __attribute__((packed)) gate_desc_t;

#define PTR_LOW(x) ((unsigned long long)(x) & 0xFFFF)
#define PTR_MIDDLE(x) (((unsigned long long)(x) >> 16) & 0xFFFF)
#define PTR_HIGH(x) ((unsigned long long)(x) >> 32)

#define gate_offset(g) ((g)->offset_low | ((unsigned long)(g)->offset_middle << 16) | ((unsigned long)(g)->offset_high << 32))
#define gate_ptr(base, idx) ((gate_desc_t*) (((void*) base) + idx*sizeof(gate_desc_t)))
```
x86-64 IDT의 16바이트 게이트 디스크립터를 그대로 표현하고 있습니다. IDT는 **Interrupt Descriptor Table** 의 약자로 인터럽트나 예외가 발생했을 때 어떤 핸들러 함수를 실행할지 저장해둔 테이블입니다. 테이블의 각 엔트리가 핸들러 함수 주소를 담고 있고, 각 엔트리가 `gate_desc_t` 하나입니다. 핸들러 주소가 `offset_low + offset_middle + offset_high` 세 부분으로 나뉘어져 있습니다. 주소 조립/분해용 매크로가 아래에 존재하는 것을 볼 수 있습니다. `install_kernel_irq_hanlder()` 함수에서 **isr_wrapper** 함수 주소를 이 세 필드에 분해해서 사용합니다.

```c
#define KERNEL_DPL          0
#define USER_DPL            3
#define GDT_ENTRY_USER_CS   6
#define GDT_ENTRY_KERNEL_CS 2

typedef enum {
    KERNEL_CS = GDT_ENTRY_KERNEL_CS*8+KERNEL_DPL,
    USER_CS   = GDT_ENTRY_USER_CS*8+USER_DPL,
} cs_t;
```
핸드러를 커널 권한(Ring 0)으로 설치하기 위한 상수들로, `gate_desc_t.segment`에 **KERNEL_CS**, `gate_desc_t.dpl`에 **KERNEL_DPL** 을 넣으면 커널 수준 인터럽트 핸들러가 됩니다. 

```c
typedef struct {
    uint16_t size;
    uint64_t base;
} __attribute__((packed)) dtr_t;
```
`SIDT` 명령어 결과(IDTR 레지스터)를 받는 메모리 레이아웃이라 `__attribute__((packed))__`가 필수입니다. 

#### include/linux/tdx_step.h
```c
typedef struct {
    //모니터링 대상
	uint64_t *target_vaddrs;         // 측정할 가상 주소 배열
	uint64_t target_vaddrs_len;      // 배열 길이
	uint64_t offset_in_target_vaddr; // 페이지 내 오프셋

	// 캐시 미스 임계값
	uint64_t miss_thresh;

    // 스레드 간 동기화
	int status; // 0=실행중, 1=종료요청, 2=종료됨, 3=메모리 동기화 요청
	spinlock_t status_lock;

	void *dummy_page;

	// 측정 결과
	uint64_t lowest_diff;      // 최소 접근 시간
	uint64_t highest_diff;     // 최대 접근 시간
	uint64_t hit_counter;      // 캐시 히트 횟수
	uint64_t total_iterations; 
	uint64_t *timings;         // 타이밍 기록 배열
	uint64_t timings_len;
} fr_monitor_thread_ctx_t;
```
fr은 Flush+Reload 공격을 의미하며, `fr_monitor_thread_ctx_t`는 **STUMBLE_STEP** 공격에서 별개의 쓰레드가 캐시 모니터링을 할 때 쓰는 컨텍스트 구조체입니다. 

```c
typedef struct {
    gate_desc_t *base;
    size_t     entries;
} idt_t;

typedef struct {
    uint32_t lvtt;
    uint32_t tdcr;
    uint32_t tmict;
} apic_backup_t;
```
`idt_t`는 IDT 테이블의 시작 주소를 나타내고, `apic_backup_t`는 APIC 타이머의 **lvtt(타이머 모드)**, **tdcr(분주비)**, **tmict(카운터 초기값)** 세 레지스터를 저장해두었다가 공격 후 복원하는 용도입니다. 

```c
typedef enum {
	AS_INACTIVE,
	//Waiting for attack configuration to be applied
	AS_SETUP_PENDING,
	//wait for pagefault on target gpa
	AS_WAITING_FOR_TARGET,
	//Single step until we get parge fault for done marker
	AS_WAITING_FOR_DONE_MARKER,
	//We got our target and are now waiting for the end of the sequence
	AS_WAITING_FOR_END_OF_SEQ,
	//We got an unexpected access during AS_WAITING_FOR_DONE_MARKER and are now waiting for a trigger to return to that state
	AS_WAITING_FOR_REENTER,
	//Waiting for single step configuration to be cleared
	AS_TEARDOWN_PENDING,
	AS_MAX,
} attack_state_t;
```
공격 전체 진행 상태를 나타내는 enum입니다. 상태 머신의 각 단계를 의미합니다.

```c
#define TDX_STEP_SHARED_SIGBUF_PAGES 256
```
FREQ_SNEAK 모드(single-step으로 추정됨) 전용으로, TD가 연산 결과를 호스트와 공유하기 위한 메모리 채널을 만들 때 사용하는 상수입니다.

`attack_cfg_t` 구조체는 공격의 전체 생애주기를 관리하는 **중앙 제어 및 상태 저장 구조체** 입니다.
```c
typedef struct {

	//
	// Stumble Step Specific
	//

	//store cache hit results. Has len `want_attack_iterations`
	uint64_t* stumble_step_hit_counter_data;
	//store tdexit count results. Has len `want_attack_iterations`
	uint64_t* stumble_step_exit_count_data;
```
StumbleStepping 공격에서 **iteration별 Flush+Reload 히트 횟수**, **iteration별 TDEXIT 횟수** 를 `의미합니다.

```c
	//
	// Freq Sneak Specific
	//

	//max number of elements that we can store for a single iteration (i.e. an inner array in freq_sneak_events_by_iteration)
	uint64_t freq_sneak_iteration_max_entries;
	//each entry holds the next free idx. In the end, we have the actual length
	uint64_t* freq_sneak_events_by_iteration_next_idx;
	//2D array with one inner array per iteration
	freq_sneak_event_t** freq_sneak_events_by_iteration;

	uint64_t shared_sigbuf_gpa;
	struct page* pinned_page_shared_sigbuf[TDX_STEP_SHARED_SIGBUF_PAGES];
    uint8_t* mapping_shared_sigbuf; 
```
**freq_sneak_event_t** 는 TDEXIT 한 번마다 생성되는 측정 레코드로, kvm.h에 정의되어 있습니다. **freq_sneak_events_by_iteration** 배열은 2차원 배열 구조로, victim을 한번 실행시키면서 관측한 각 iteration에 대한 기록들을 저장합니다. 아래 변수들은 신호 전달에 사용하는 공유 메모리 버퍼와 관련된 변수들입니다.

```c
    //if true, do the page tracking and the apic timer setup/teardown but not the actual apic timer programming
	bool debug_mode;

	//one attack == one `target_trigger_sequence` cycle. This tracks the number of cycles
	uint64_t current_attack_iteration_idx;
	uint64_t want_attack_iterations;

	uint64_t target_gpa;
	//tracking sequence to stop at the desired execution of target_gpa
	uint64_t* target_trigger_sequence; //TODO: rename to something like "program model"
	uint64_t target_trigger_sequence_len;
```
`debug_mode`는 테스트 용도이고, 다음 두 변수는 **전체 공격 시도 횟수** 를 관리합니다. 나머지 부분은 트리거 시퀀스를 관리하는 부분으로 `target_gpa`는 싱글 스테핑 공격을 시작하고 싶은 최종 목적지 주소, `target_trigger_sequence`는 특정 메모리 페이지들에 접근하는 순서를 이용하여 공격 타이밍을 잡을 때 사용됩니다. 

```c
    //entry from target_trigger_sequence that is currently tracked. Only valid while in AS_WAITING_FOR_TARGET state
	uint64_t tts_idx;
	//position in `target_trigger_sequence` at which we want to launch our attack
	uint64_t tts_attack_pos;

	uint64_t* attack_phase_allowed_gpas;
	uint64_t attack_phase_allowed_gpas_len;

	uint64_t done_marker_gpa;
	attack_state_t state;
	uint64_t *ignored_gpas;
	uint64_t ignored_gpas_len;
```
`tts_attack_pos`는 `tts_idx`가 특정 값에 도달했을 때 **AS_WAITING_FOR_DONE_MARKER** 로 전환되어 싱글 스테핑을 시작하는 값입니다. `attack_phase_allowed_gpas`는 접근이 허용되는 GAP 목록이고, `done_marker_gpa`는 iteration의 종료 지점을 나타냅니다. `ignored_gpas`는 무시할 GPA 목록입니다.

```c
    //used to track unrelated faults during the AS_WAITING_FOR_DONE_MARKER state
	uint64_t unrelated_faults[30];
	//actually used length of "unrelated_faults" in the last attack run
	uint64_t unrelated_faults_used_len;
```
공격이 진행되는 동안 **예상치 못한 노이즈** 를 기록하고 분석하기 위한 레코더입니다. allow gpas 이외의 곳에서 발생한 페이지 폴트 주소들을 기록하여 iteration의 신뢰도를 결정합니다. 

```c
	//True if most recent TD GPA fault was due to instruction fetch
	bool last_fault_exec;
	//True if most recent TD GPA fault was due to write
	bool last_fault_write;
	// True if most recent TD GPA fault was due to read
	bool last_fault_read;

	//timetamp in nano seconds. Used to compute required time for attack.
	uint64_t start_time;

	//sequential counter used to give event a unique id
	uint64_t event_id;
} attack_cfg_t;
```
`last_*` 변수들은 가장 최근에 발생한 페이지 폴트의 원인(rwx)을 저장합니다. `start_time`이랑 `event_id`는 각각 걸리는 시간 분석을 위해 사용하거나 이벤트 고유 식별자를 나타냅니다. 

`tdx_step_config_t`는 공격 전체를 담는 최상위 구조체로, 전역 변수의 형태로 하나만 존재합니다. 내부에 attack_cfg_t가 선언되어 있는 것을 볼 수 있습니다.
```c
typedef struct {
    uint32_t timer_value;
    uint64_t entries_since_stepping_attack;
    //number of entries during the active attack phase
	uint64_t entries_while_active_stepping_attack;
```


#### arch/x86/kvm/tdx_step.c

### 커널 패치
#### arch/x86/virt/vmx/tdx/tdxcall.S

#### arch/x86/virt/vmx/tdx/seamcall.S

#### arch/x86/kvm/vmx/tdx.c

#### arch/x86/kvm/mmu/tdp_mmu.c

#### arch/x86/kvm/mmu/mmu.c

#### arch/x86/kvm/x86.c

#### arch/x86/mm/pat/set_memory.c

#### include/uapi/linux/kvm.h

#### virt/kvm/kvm_main.c

#### arch/x86/include/asm/tdx.h

#### drivers/virt/coco/tdx-guest/tdx-guest.c

### our-attack-tools

### our-kernel-patches

## 실제 세팅
1. 소스 언패킹
```
dpkg-source -x linux-intel-opt_6.5.0-1003.3.dsc 
```

2. 커널 패치 적용
```
cd linux-intel-opt-6.5.0/
patch -p1 < ../../our-kernel-patches/single-stepping-patch.patch
```

3. 빌드 (서버 환경에 flex, bison 같은 빌드 의존성이 없어 로컬에서 빌드를 진행했습니다. 아키텍처는 같아야 합니다)
```
bash make-kernel.sh
```

4. 커널 설치할 환경에서 dpkg 및 재부팅 순서 조정
```
sudo dpkg -i linux-image-6.5.3-its-tdx_6.5.3-2_amd64.deb linux-headers-6.5.3-its-tdx_6.5.3-2_amd64.deb

sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux 6.5.3-its-tdx"
sudo reboot
```

이제 TD에 들어갈 이미지를 구성해야 합니다. 일단 아티팩트의 `our_run_td.sh`에서 사용하고 있는 버전을 그대로 사용하고자 합니다: **tdx-guest-ubuntu-23.10.qcow2**

다만 23.10 버전 이미지를 만들려면 `create-td-image.sh` 스크립트를 좀 수정해야 합니다. 23.10은 EOL이라 공식 지원 버전에서 벗어났기 때문입니다. 따라서 클라우드 이미지 다운로드 경로를 **old-releases.ubuntu.com** 으로 바꿔야 합니다. 그리고 스크립트를 사용할 때는 저 스크립트 외에도 tdx 폴더에 존재하는 여러 파일들이 필요합니다. 

<details>
<summary> 수정된 스크립트 (338 ~ 332 line 추가, 335 ~ 345 line 추가) </summary>

```bash
#!/bin/bash

# This source code is a modified copy of https://github.com/intel/tdx-tools.git
# See LICENSE.apache file for original license information.

# This file is part of Canonical's TDX repository which includes tools
# to setup and configure a confidential computing environment
# based on Intel TDX technology.
# See the LICENSE file in the repository for the license text.

# Copyright 2024 Canonical Ltd.
# SPDX-License-Identifier: GPL-3.0-only

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3,
# as published by the Free Software Foundation.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranties
# of MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.

# This script will create a TDX guest image (qcow2 format) from a cloud
# image that is released at : https://cloud-images.ubuntu.com
# The cloud image is released as qcow3/qcow2 image (with .img suffix)
# The image comes with only 2 partitions:
#   - rootfs (~2G -> /)
#   - BIOS Boot (4M)
#   - EFI partition (~100M -> /boot/efi/ partition)
#   - Ext boot (/boot/ partition)
#
# As first step, we will resize the rootfs partition to a bigger size
# As second step, we will boot up the image to run cloud-init (using virtinst)
# and finally, we use virt-customize to copy in and run TDX setup script
#
# TODO : ask cloud init to run the TDX setup script

# User can tune the current script by providing arguments to the script
# or setting following environment variables:

# UBUNTU_VERSION: the ubuntu version (24.04, 24.10, ...)
# GUEST_USER: the username in the image
# GUEST_PASSWORD: the user password in the image
# GUEST_HOSTNAME: the guest hostname

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# source config file
if [ -f ${SCRIPT_DIR}/../../setup-tdx-config ]; then
    source ${SCRIPT_DIR}/../../setup-tdx-config
fi

LOGFILE=/tmp/tdx-guest-setup.txt
FORCE_RECREATE=false
TMP_GUEST_IMG_PATH="/tmp/tdx-guest-tmp.qcow2"
SIZE=100
GUEST_USER=${GUEST_USER:-"tdx"}
GUEST_PASSWORD=${GUEST_PASSWORD:-"123456"}
GUEST_HOSTNAME=${GUEST_HOSTNAME:-"tdx-guest"}

ok() {
    echo -e "\e[1;32mSUCCESS: $*\e[0;0m"
}

error() {
    echo -e "\e[1;31mERROR: $*\e[0;0m"
    cleanup
    exit 1
}

warn() {
    echo -e "\e[1;33mWARN: $*\e[0;0m"
}

info() {
    echo -e "\e[0;33mINFO: $*\e[0;0m"
}

check_tool() {
    [[ "$(command -v $1)" ]] || { error "$1 is not installed" 1>&2 ; }
}

# On Ubuntu noble 24.04
# if passt is install and virt-customize runs as root, virt-customize
# will fail, this is a work-around for this issue
# Furthermore, we see some instability to reach ubuntu archive when
# passt is used on 24.10, so for now, we decide to remove it
# for both 24.04 and 24.10
workaround_passt() {
    if command -v passt 2>&1 > /dev/null ; then
       echo "You have the package passt installed, this will prevent"
       echo "  the script to work properly. This package has to be removed:"
       apt autoremove passt
    fi
}

usage() {
    cat <<EOM
Usage: $(basename "$0") [OPTION]...
  -h                        Show this help
  -f                        Force to recreate the output image
  -n                        Guest host name, default is "tdx-guest"
  -u                        Guest user name, default is "tdx"
  -p                        Guest password, default is "123456"
  -s                        Specify the size of guest image
  -v                        Ubuntu version (24.04, 25.04)
  -o <output file>          Specify the output file, default is tdx-guest-ubuntu-<version>.qcow2.
                            Please make sure the suffix is qcow2. Due to permission consideration,
                            the output file will be put into /tmp/<output file>.
EOM
}

process_args() {
    while getopts "v:o:s:n:u:p:r:fch" option; do
        case "$option" in
        o) GUEST_IMG_PATH=$(realpath "$OPTARG") ;;
        s) SIZE=${OPTARG} ;;
        n) GUEST_HOSTNAME=${OPTARG} ;;
        u) GUEST_USER=${OPTARG} ;;
        p) GUEST_PASSWORD=${OPTARG} ;;
        f) FORCE_RECREATE=true ;;
        v) UBUNTU_VERSION=${OPTARG} ;;
        h)
            usage
            exit 0
            ;;
        *)
            echo "Invalid option '-${OPTARG}'"
            usage
            exit 1
            ;;
        esac
    done

    if [[ -z "${UBUNTU_VERSION}" ]]; then
        error "Please specify the ubuntu release by setting UBUNTU_VERSION or passing it via -v"
    fi

    # generate variables
    CLOUD_IMG="ubuntu-${UBUNTU_VERSION}-server-cloudimg-amd64.img"
    CLOUD_IMG_PATH=$(realpath "${SCRIPT_DIR}/${CLOUD_IMG}")

    # output guest image, set it if user does not specify it
    if [[ -z "${GUEST_IMG_PATH}" ]]; then
        if [[ "${TDX_SETUP_INTEL_KERNEL}" == "1" ]]; then
	    GUEST_IMG_PATH=$(realpath "tdx-guest-ubuntu-${UBUNTU_VERSION}-intel.qcow2")
        else
	    GUEST_IMG_PATH=$(realpath "tdx-guest-ubuntu-${UBUNTU_VERSION}-generic.qcow2")
        fi
    fi

    if [[ "${CLOUD_IMG_PATH}" == "${GUEST_IMG_PATH}" ]]; then
        error "Please specify a different name for guest image via -o"
    fi

    if [[ ${GUEST_IMG_PATH} != *.qcow2 ]]; then
        error "The output file should be qcow2 format with the suffix .qcow2."
    fi
}

download_image() {
    # Get the checksum file first
    if [[ -f ${SCRIPT_DIR}/"SHA256SUMS" ]]; then
        rm ${SCRIPT_DIR}/"SHA256SUMS"
    fi

    OFFICIAL_UBUNTU_IMAGE="https://cloud-images.ubuntu.com/releases/${UBUNTU_VERSION}/release/"
    wget "${OFFICIAL_UBUNTU_IMAGE}/SHA256SUMS" -O ${SCRIPT_DIR}/"SHA256SUMS"

    while :; do
        # Download the cloud image if not exists
        if [[ ! -f ${CLOUD_IMG_PATH} ]]; then
            wget -O ${CLOUD_IMG_PATH} ${OFFICIAL_UBUNTU_IMAGE}/${CLOUD_IMG}
        fi

        # calculate the checksum
        download_sum=$(sha256sum ${CLOUD_IMG_PATH} | awk '{print $1}')
        found=false
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" == *"$CLOUD_IMG"* ]]; then
                if [[ "${line%% *}" != ${download_sum} ]]; then
                    echo "Invalid download file according to sha256sum, re-download"
                    rm ${CLOUD_IMG_PATH}
                else
                    ok "Verify the checksum for Ubuntu cloud image."
                    return
                fi
                found=true
            fi
        done < ${SCRIPT_DIR}/"SHA256SUMS"
        if [[ $found != "true" ]]; then
            echo "Invalid SHA256SUM file"
            exit 1
        fi
    done
}

create_guest_image() {
    if [ ${FORCE_RECREATE} = "true" ]; then
        rm -f ${CLOUD_IMG_PATH}
    fi

    download_image

    # this image will need to be customized both by virt-customize and virt-install
    # virt-install will interact with libvirtd and if the latter runs in normal user mode
    # we have to make sure that guest image is writable for normal user
    install -m 0777 ${CLOUD_IMG_PATH} ${TMP_GUEST_IMG_PATH}
    if [ $? -eq 0 ]; then
        ok "Copy the ${CLOUD_IMG} => ${TMP_GUEST_IMG_PATH}"
    else
        error "Failed to copy ${CLOUD_IMG} to /tmp"
    fi

    resize_guest_image
}

# To resize the guest image
# 1) we add additional space to the qcow image using qemu-img tool
# 2) we extend (using growpart) the partition sda1 to fill empty space until end of disk
#    since sda1 is the last partition, it will take all space we previously added
# 3) we resize the file system to cover all partition space
#
# NB: We should not use static name for the disk device (sda) because it can
# change on boot (e.g., the main disk might be named sdb). Using sda naming can cause failure
# of the resizeing operation from time to time.
# Instead, we access the disk by ID:
#
# /dev/disk/by-id:
# total 0
# lrwxrwxrwx 1 0 0  9 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_appliance -> ../../sdb
# lrwxrwxrwx 1 0 0  9 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_hd0 -> ../../sda
# lrwxrwxrwx 1 0 0 10 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_hd0-part1 -> ../../sda1
# lrwxrwxrwx 1 0 0 11 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_hd0-part14 -> ../../sda14
# lrwxrwxrwx 1 0 0 11 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_hd0-part15 -> ../../sda15
# lrwxrwxrwx 1 0 0 11 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_hd0-part16 -> ../../sda16
resize_guest_image() {
    qemu-img resize ${TMP_GUEST_IMG_PATH} +${SIZE}G
    virt-customize -a ${TMP_GUEST_IMG_PATH} \
        --no-network \
        --run-command 'growpart /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_hd0 1' \
        --run-command 'resize2fs /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_hd0-part1' \
        --run-command 'systemctl mask pollinate.service'
    if [ $? -eq 0 ]; then
        ok "Resize the guest image to ${SIZE}G"
    else
        error "Failed to resize guest image to ${SIZE}G"
    fi
}

config_cloud_init_cleanup() {
  virsh shutdown tdx-config-cloud-init &> /dev/null
  sleep 1
  virsh destroy tdx-config-cloud-init &> /dev/null
  virsh undefine tdx-config-cloud-init &> /dev/null
}

apply_cloud_init_conf() {
  virt_type=$1
  virt-install --debug --memory 4096 --vcpus 4 --name tdx-config-cloud-init \
     --disk ${TMP_GUEST_IMG_PATH} \
     --disk /tmp/ciiso.iso,device=cdrom \
     --os-variant ubuntu${UBUNTU_VERSION} \
     --virt-type ${virt_type} \
     --graphics none \
     --import \
     --wait=12 &>> ${LOGFILE}
}


config_cloud_init() {
    pushd ${SCRIPT_DIR}/cloud-init-data
    [ -e /tmp/ciiso.iso ] && rm /tmp/ciiso.iso
    cp user-data.template user-data
    cp meta-data.template meta-data

    # configure the user-data
    cat <<EOT >> user-data

user: $GUEST_USER
password: $GUEST_PASSWORD
chpasswd: { expire: False }
EOT

    # configure the meta-dta
    cat <<EOT >> meta-data

local-hostname: $GUEST_HOSTNAME
EOT

    info "Generate configuration for cloud-init..."
    genisoimage -output /tmp/ciiso.iso -volid cidata -joliet -rock user-data meta-data
    info "Apply cloud-init configuration with virt-install..."
    info "(Check logfile for more details ${LOGFILE})"
    popd

    apply_cloud_init_conf kvm
    RET=$?
    if [ ${RET} -eq 0 ]; then
        ok "Apply cloud-init configuration with virt-install"
        sleep 1
    else
        # if the failure is caused by lack of KVM support
        # try qemu virt type
        if [ ! -f /dev/kvm ]; then
            apt install --yes qemu-system-x86
            apply_cloud_init_conf qemu
            RET=$?
        fi
    fi
    if [ ${RET} -ne 0 ]; then
        warn "Please increase wait time(--wait=12) above and try again..."
        error "Failed to configure cloud init. Please check logfile \"${LOGFILE}\" for more information."
    fi

    config_cloud_init_cleanup
}

fix_eol_apt_sources() {
    # Ubuntu EOL releases are moved from archive.ubuntu.com to old-releases.ubuntu.com
    # Ubuntu 23.10+ uses DEB822 format at /etc/apt/sources.list.d/ubuntu.sources
    virt-customize -a ${TMP_GUEST_IMG_PATH} \
        --run-command "sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true" \
        --run-command "sed -i 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true" \
        --run-command "sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true" \
        --run-command "sed -i 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true"
    if [ $? -eq 0 ]; then
        ok "Updated apt sources to old-releases.ubuntu.com for EOL release"
    else
        error "Failed to update apt sources"
    fi
}

setup_guest_image() {
    info "Run setup scripts inside the guest image. Please wait (can take > 10 minutes) ..."

    # For EOL Ubuntu releases, redirect apt sources to old-releases.ubuntu.com
    local eol_versions=("23.10" "23.04" "22.10" "21.10" "21.04" "20.10")
    for eol_ver in "${eol_versions[@]}"; do
        if [[ "${UBUNTU_VERSION}" == "${eol_ver}" ]]; then
            info "Ubuntu ${UBUNTU_VERSION} is EOL, fixing apt sources..."
            fix_eol_apt_sources
            break
        fi
    done

    virt-customize -a ${TMP_GUEST_IMG_PATH} \
       --mkdir /tmp/tdx/ \
       --copy-in ${SCRIPT_DIR}/setup.sh:/tmp/tdx/ \
       --copy-in ${SCRIPT_DIR}/../../setup-tdx-guest.sh:/tmp/tdx/ \
       --copy-in ${SCRIPT_DIR}/../../setup-tdx-common:/tmp/tdx \
       --copy-in ${SCRIPT_DIR}/../../setup-tdx-config:/tmp/tdx \
       --copy-in ${SCRIPT_DIR}/../../attestation/:/tmp/tdx \
       --copy-in ${SCRIPT_DIR}/../../tests/lib/tdx-tools/:/tmp/tdx \
       --run-command "/tmp/tdx/setup.sh"
    if [ $? -eq 0 ]; then
        ok "Run setup scripts inside the guest image"
    else
        error "Failed to setup guest image"
    fi
}

cleanup() {
    if [[ -f ${SCRIPT_DIR}/"SHA256SUMS" ]]; then
        rm ${SCRIPT_DIR}/"SHA256SUMS"
    fi
    info "Cleanup!"
}

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# remove log file to avoid `permission denied` error if the file already exists and owned by a different user
# recently, on Ubuntu and Debian, the syctl variable fs.protected_regular is set to 2
# that will prevent root from writing to file owned by a different user
rm -f ${LOGFILE}
echo "=== tdx guest image generation === " > ${LOGFILE}

# sanity cleanup
config_cloud_init_cleanup

# install required tools
apt install --yes qemu-utils libguestfs-tools virtinst genisoimage libvirt-daemon-system &>> ${LOGFILE}

# to allow virt-customize to have name resolution, dhclient should be available
# on the host system. that is because virt-customize will create an appliance (with supermin)
# from the host system and will collect dhclient into the appliance
apt install --yes isc-dhcp-client &>> ${LOGFILE}

check_tool qemu-img
check_tool virt-customize
check_tool virt-install
check_tool genisoimage
workaround_passt

info "Installation of required tools"

process_args "$@"

create_guest_image

config_cloud_init

setup_guest_image

cleanup

mv ${TMP_GUEST_IMG_PATH} ${GUEST_IMG_PATH}
chmod a+rw ${GUEST_IMG_PATH}

ok "TDX guest image : ${GUEST_IMG_PATH}"
```
