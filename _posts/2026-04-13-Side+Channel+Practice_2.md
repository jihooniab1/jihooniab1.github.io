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

## 아티팩트
```
user@Ubuntu:~/Downloads/tdxdown-paper-artifacts/tdxdown-paper-artifacts$ ls -l
total 16
drwxr-xr-x 2 user user 4096 Apr 28  2024 'bios screenshots'
-rw-rw-r-- 1 user user 2065 Apr 29  2024  README.md
drwxrwxr-x 5 user user 4096 Apr 27  2024  single-stepping
drwxrwxr-x 5 user user 4096 Apr 28  2024  stumble-stepping
```

본 포스팅에서는 **single-stepping** 공격 관련 코드들을 분석하고 6.8.0 canonical/intel 커널에 이식해보고자 합니다.

### 자료구조 및 헤더
#### include/uapi/linux/kvm.h
```c
typedef struct {
	uint64_t gpa;
} tdx_step_block_page_t;
#define TDX_STEP_BLOCK_PAGE _IOWR(KVMIO, 0xf0, tdx_step_block_page_t)

typedef struct {
	uint64_t gpa;
} tdx_step_unblock_page_t;
#define TDX_STEP_UNLBOCK_PAGE _IOWR(KVMIO, 0xf1, tdx_step_unblock_page_t)

typedef struct {
	uint64_t cpu_id;
}tdx_step_send_ipi_t;
//send nmi ipi to selected cpu
#define TDX_STEP_SEND_IPI _IOWR(KVMIO, 0xf2, tdx_step_send_ipi_t)
...
```
`구조체 + 구조체를 인자로 쓰는 KVM ioctl 선언` 형태로 공격에 사용하는 ioctl들이 선언되어 있습니다. 종류는 다음과 같습니다.

| 번호 | 매크로 | 매크로 종류 | 인자 struct | 방향 | 역할 |                                                                                                                                 
|------|--------|-------------|-------------|------|------|                                                                                                                                 
| 0xf0 | TDX_STEP_BLOCK_PAGE | _IOWR | tdx_step_block_page_t | in | 지정 GPA 페이지 SEPT block |                                                                                            
| 0xf1 | TDX_STEP_UNLBOCK_PAGE | _IOWR | tdx_step_unblock_page_t | in | 위 block 해제 |                                                                                       
| 0xf2 | TDX_STEP_SEND_IPI | _IOWR | tdx_step_send_ipi_t | in | 지정 CPU에 NMI IPI 발사 |
| 0xf3 | TDX_STEP_FR_VMCS | _IOWR | tdx_step_fr_vmcs_t | in/out | 공격 메인 - config 넘기고 상태 머신 시작 |                                                                                
| 0xf4 | TDX_STEP_TERMINATE_FR_VMCS | _IOWR | tdx_step_terminate_fr_vmcs_t | in/out | 공격 종료 + 측정 결과 회수 |                                                                          
| 0xf5 | TDX_STEP_SET_REMAINING_CACHE_ATTACKS | _IO | 없음 | - | F+R 잔여 카운터 리셋 |                                                                                                     
| 0xf6 | TDX_STEP_IS_FR_VMCS_DONE | _IOWR | tdx_step_is_fr_vmcs_done_t | out | 공격 완료 여부 polling |                                                                                     
| 0xf7 | TDX_STEP_MAP_GPA | _IOWR | tdx_step_map_gpa_t | in/out | GPA → HPA 매핑 조회 |         

#### include/linux/tdx_step.h
`tdx_step.h`는 **공격 상태를 담는 구조체와 부속물 모음** 을 담고 있는 파일입니다. 공격은 7개 상태로 구성되어 있고 아래와 같습니다. 
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

그리고 `tdx_step_config_t` 구조체는 config를 받아 공격 설정을 저장하고, 공격 전체의 상태(`attack_cfg.state`)를 관리하는 구조체로, 공격 한 사이클의 정보를 모두 담고 있습니다.
```c
typedef struct {
    uint32_t timer_value;
    uint64_t entries_since_stepping_attack;
    //number of entries during the active attack phase
	uint64_t entries_while_active_stepping_attack;
    apic_backup_t apic_backup;
    attack_cfg_t attack_cfg;

    //set this flag if we supressed an interrupt during our stepping attack
    bool suppressed_interrupt_during_stepping;
	int suppressed_interrupt_delivery_mode;
	int suppressed_interrupt_trig_mode;
	int suppressed_interrupt_vector;

    bool block_gpa_valid;
    uint64_t block_gpa;
    uint64_t gpa_blocked;
    
    struct page* pinned_page_shared_mem;
    uint64_t* mapping_shared_mem; 

    //might be 0, if feature not activated by user
    uint8_t* mapping_victim_code;



    //idt related vars

    /// @brief core on which idt was retrieved or -1 if idt has never been fetched
	int got_idt_on_cpu;
	/// @brief if got_idt_on_cpu != -1, this holds the idt for that core
	idt_t idt;
    gate_desc_t old_idt_gate;
    bool running_with_custom_apic_handler;

    /* if this array is not null,
     * access these tdvps pages directly before VM entry
     * and again after VM exit
    */
    uint64_t* targeted_tdvps_addrs;
    uint64_t targeted_tdvps_addrs_len;

    uint64_t* all_tdvps_addrs;
    uint64_t* timings_all_tdvps_addrs;
    uint64_t all_tdvps_addrs_count;
	//might be NULL if attack type not STUMBLE_STEP
    volatile uint64_t* attacked_tdvps_addr;


    //Track if we have already called my_split_all_pages for this VM
	bool called_split_pages;
    fr_monitor_thread_ctx_t *fr_ctx;

	//type of attack that should be performed
	attack_type_t attack_type;
} tdx_step_config_t;
```

### 저수준 SEMCALL / 어셈블리
#### arch/x86/virt/vmx/tdx
tdxcall.S는 SEAMCALL/TDCALL을 발사하는 어셈블리 헬퍼입니다. SEAMCALL은 KVM이 TDX 모듈에게 TD 관련 요청을 보낼 때 사용하고, TDCALL은 TD가 게스트 OS의 자원 요청을 TDX 모듈에게 보낼 때 사용합니다. 호스트 커널 스케줄러가 QEMU의 vCPU 스레드를 깨우는 상황을 살펴보겠습니다. QEMU 버전은 8.2.2 코드를 참고하였습니다.

QEMU는 vCPU를 스레드 형태로 관리합니다. 스레드가 스케줄링 되면 vCPU가 CPU를 빌려 실행을 하는 구조라고 생각할 수 있습니다.
```c
static void *kvm_vcpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;
    int r;

    rcu_register_thread();

    qemu_mutex_lock_iothread();
    qemu_thread_get_self(cpu->thread);
    cpu->thread_id = qemu_get_thread_id();
    cpu->neg.can_do_io = true;
    current_cpu = cpu;

    r = kvm_init_vcpu(cpu, &error_fatal);
    kvm_init_cpu_signals(cpu);

    /* signal CPU creation */
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    do {
        if (cpu_can_run(cpu)) {
            r = kvm_cpu_exec(cpu);
            if (r == EXCP_DEBUG) {
                cpu_handle_guest_debug(cpu);
            }
        }
        qemu_wait_io_event(cpu);
    } while (!cpu->unplug || cpu_can_run(cpu));

    kvm_destroy_vcpu(cpu);
    cpu_thread_signal_destroyed(cpu);
    qemu_mutex_unlock_iothread();
    rcu_unregister_thread();
    return NULL;
}
```
`kvm_vcpu_thread_fn` 함수는 **QEMU가 vCPU 개수만큼 만든 pthread의 진입 함수** 입니다. 

초반부에는 RCU에 스레드를 등록하고 커널에 vCPU 자료구조를 만든 후 **vCPU 준비됨** 시그널을 생성합니다. 중반의 메인 루프에서는 

### APIC export

### ioctl 진입점 + 전역 config

### SEAMCALL 패스 (TD enter/exit)

### 페이지 폴트 패스

### teardown

## 실제 세팅
1. 6.8.0 canonical/intel 커널 소스코드 다운받기
```
dpkg-source -x linux-intel-opt_6.5.0-1003.3.dsc 
```

2. 커널 패치 포팅

3. 빌드 및 deb 패키징

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
