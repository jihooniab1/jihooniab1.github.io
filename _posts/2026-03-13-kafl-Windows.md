---
title: "kAFL 퍼저 세팅하고 Windows 11 25H2 환경 구축하기"
date: 2026-03-13 00:00:00 +0900
categories: [Study]
tags: [fuzzing]
permalink: /posts/kafl-Windows/
math: true
---

## kAFL 빌드 및 설치
https://intellabs.github.io/kAFL/tutorials/installation.html

본 링크를 참고하여 진행했고, 우분투 24.04 환경을 사용했습니다. 프로세서가 Intel PT를 지원해야 하기 때문에 아래 커맨드로 확인해볼 수 있습니다.
```
echo -n "Intel PT support: "; if $(grep -q "intel_pt" /proc/cpuinfo); then echo "✅"; else echo "❌"; fi
```

필요한 소프트웨어를 설치해줍니다.
```
sudo apt-get install -y python3-dev python3-venv git build-essential libffi-dev gcc-mingw-w64-x86-64
```

그 후에 kAFL 레포를 클론하고 **배포** 를 하면 자동으로 실행이 됩니다.
```
git clone https://github.com/IntelLabs/kAFL.git
cd kAFL

make deploy
```

필요할 때 비밀번호만 넣고 기다리면 아래와 같이 설치가 완료됩니다. <br>
![kafl_1](/assets/img/posts/Study/kafl_1.png) <br>

그리고 리부팅을 해준 다음 새로 추가된 커널을 실행해주면 됩니다. 그래야 **KVM-Nyx** 를 사용할 수 있습니다. 재부팅 후 성공적으로 새로운 커널이 실행되면 아래와 같이 KVM-nyx를 확인할 수 있습니다. <br>

![kafl_2](/assets/img/posts/Study/kafl_2.png) <br>

`env` 타겟을 실행해줍니다. 아래와 같이 나오면 성공입니다. <br>

![kafl_3](/assets/img/posts/Study/kafl_3.png) <br>

## Windows VM 설정
### Windows qcow2 만들기
저는 kAFL의 템플릿으로 제공된 파일들을 사용하지 않고 직접 세팅을 해보기로 하였습니다. 먼저 Windows11 운영체제가 설치되어 있는 qcow2 이미지를 준비해야 합니다. 아래 패키지들을 설치해줍니다.

```
sudo apt install qemu-system qemu-utils qemu-block-extra​ 
```

그리고 edk2로 직접 ovmf 펌웨어 이미지를 빌드하겠습니다. 의존성 패키지를 준비해줍니다.

```
sudo apt update && sudo apt install -y \
    automake autoconf bash coreutils expect libtool sed \
    libssl-dev libtpms-dev fuse libfuse2 libfuse-dev \
    libglib2.0-0 libglib2.0-dev libjson-glib-dev \
    net-tools python3 python3-twisted \
    selinux-policy-dev socat \
    gnutls-bin libgnutls28-dev \
    libtasn1-6 libtasn1-bin libtasn1-dev \
    rpm libseccomp-dev nasm acpica-tools swtpm
```

edk2 코드를 클론해줍니다.
```
git clone https://github.com/tianocore/edk2.git
cd edk2
```

다음 커맨드를 실행합니다.
```
git submodule update --init --recursive
make -C BaseTools
source ./edksetup.sh
```

그리고 빌드 커맨드를 실행하면 됩니다. 저는 레지스터 조작해서 TPM 우회하고 이런게 귀찮아서 아래와 같은 옵션을 넣었습니다. 빌드된 `OVMF_CODE.fd`랑 `OVMF_VARS.fd`는 **Build/OvmfX64/DEBUG_GCC/FV/OVMF_** 이 경로에 있습니다. 복사해오면 됩니다.
```
build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -b DEBUG -t GCC \
  -D SECURE_BOOT_ENABLE=TRUE \
  -D TPM_ENABLE=TRUE \
  -D TPM2_ENABLE=TRUE
```
cp 
Windows11을 설치할 빈 디스크 이미지를 만들어줍니다.
```
qemu-img create -f qcow2 Win11.qcow2 128g
```

또한 swtpm을 활용할 수 있도록 tpm.sh 스크립트도 만들어줍시다.
```
sudo mkdir /tmp/emulated_tpm

sudo swtpm socket --tpmstate dir=/tmp/emulated_tpm \
--ctrl type=unixio,path=/tmp/emulated_tpm/swtpm-sock \
--log level=20 --tpm2
```

그리고 qemu 스크립트도 준비해줍시다.
```
#!/usr/bin/env bash

TMPDIR="/tmp/emulated_tpm"

sudo mkdir -p "${TMPDIR}"

sudo swtpm socket \
  --tpmstate dir="${TMPDIR}" \
  --ctrl type=unixio,path="${TMPDIR}/swtpm-sock" \
  --log level=20 \
  --tpm2 &

sleep 1

sudo chown user:user "${TMPDIR}/swtpm-sock"

sudo qemu-system-x86_64 \
    -cpu host \
    -enable-kvm \
    -M q35 \
    -m 4096 \
    --chardev socket,id=chrtpm,path="${TMPDIR}/swtpm-sock" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 \
    -smp 4 \
    -usb \
    -device usb-tablet \
    -vga std \
    -nic user,ipv6=off,model=e1000 \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=OVMF_VARS.fd \
    -drive file=Win11.qcow2,format=qcow2 \
    -boot menu=on \
    -cdrom Windows.iso
```

실제 PC 설치하듯이 설치 과정을 따라가주시면 Windows 11 설치를 무사히 끝낼 수 있습니다. 참고로 로컬 계정으로 설치를 하려면 로그인을 요구하는 단계가 되었을 때
```
-nic none
```
qemu 스크립트를 수정하여 인터넷을 비활성화 해준 다음, 와이파이 화면에서 `oobe\bypassnro` (필요할 수도 안 할 수도 있습니다) 기법을 사용해주면 됩니다. <br>

![k5](/assets/img/posts/Study/kafl_5.png) <br>

### VM 내부 설정
qemu로 직접 실행할 때야 비밀번호도 치고 마우스로 클릭도 다 할 수 있지만, qemu-nyx로 실행하는 환경에서는 그렇게 할 수 없습니다.

그래서 VM을 들어가서 **비밀번호 없이도 로그인을 할 수 있도록** 설정을 해줘야 합니다. 구글링 하면 금방 나오니 쉽게 하실 수 있습니다.

이 설정이 끝나면 이제 직접 VM에 들어가서 조작해줘야 할 사항은 별로 없습니다.

제가 kAFL을 완벽하게 이해하지는 못했지만, 대략 파악한 퍼저 흐름은 다음과 같습니다.
1. `kafl fuzz`가 실행되면 qemu-nyx를 통해 VM이 실행됨
2. VM에 미리 넣어둔 agent 바이너리가 startup 형태로 실행됨
3. Agent는 호스트와 핸드셰이크를 수행하고, 버퍼를 할당하고 **ACQUIRE 하이퍼콜** 을 통해서 스냅샷을 찍습니다
4. 퍼징 하니스 루틴을 실행하여 사전에 주어진 입력으로 퍼징을 수행합니다.
5. **RELEASE 하이퍼콜** 을 통해 미리 촬영해둔 시점으로 즉시 롤백됩니다
6. 3-5 반복

이제 agent 바이너리를 만들어야 하는데 예제로 주어진 코드를 활용하여 다음과 같이 `test_agent.c`를 구성하였습니다. 
```c
#include <windows.h>
#include "nyx_api.h"

#define PE_CODE_SECTION_NAME ".text"

static inline void panic(void){
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
    while(1){};
}

void submit_ip_ranges() {
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule == NULL) habort("Cannot get module handle\n");

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);

    PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER)(
        (PBYTE)pNtHeaders + sizeof(IMAGE_NT_HEADERS));

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER s = &pSectionHeaders[i];
        if (memcmp(s->Name, PE_CODE_SECTION_NAME, strlen(PE_CODE_SECTION_NAME)) == 0) {
            DWORD_PTR codeStart = (DWORD_PTR)hModule + s->VirtualAddress;
            DWORD_PTR codeEnd = codeStart + s->Misc.VirtualSize;

            uint64_t buffer[3] = {0};
            buffer[0] = codeStart;
            buffer[1] = codeEnd;
            buffer[2] = 0;
            kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uint64_t)buffer);

            VirtualLock((LPVOID)codeStart, s->Misc.VirtualSize);
            return;
        }
    }
    habort("Couldn't locate .text section\n");
}

void fuzzme(uint8_t* input, int size) {
    if (size >= 5) {
        if (input[0] == 'H')
            if (input[1] == 'E')
                if (input[2] == 'L')
                    if (input[3] == 'L')
                        if (input[4] == 'O')
                            panic();
    }
}

int main(int argc, char** argv) {
    hprintf("[agent] Starting...\n");

    // 1. 초기 핸드셰이크
    kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    // 2. 모드 설정
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    // 3. 호스트 설정
    host_config_t host_config = {0};
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    hprintf("[agent] bitmap_size=0x%x, payload_size=%d\n",
            host_config.bitmap_size, host_config.payload_buffer_size);

    // 4. 페이로드 버퍼
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(
        0, host_config.payload_buffer_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    VirtualLock(payload_buffer, host_config.payload_buffer_size);
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    // 5. CR3 필터
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    // 6. 에이전트 설정 (최소한만)
    agent_config_t agent_config = {
        .agent_magic = NYX_AGENT_MAGIC,
        .agent_version = NYX_AGENT_VERSION,
    };
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

    // 7. IP 범위
    kAFL_ranges* range_buffer = (kAFL_ranges*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    memset(range_buffer, 0xff, 0x1000);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (UINT64)range_buffer);
    submit_ip_ranges();

    // 8. 퍼징 루프
    hprintf("[agent] Ready to fuzz!\n");
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);

    fuzzme(payload_buffer->data, payload_buffer->size);

    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    return 0;
}
```

그리고 이를 윈도우 환경의 컴파일러 빌드하고, qcow2 디스크 이미지에 직접 넣어주는 스크립트는 다음과 같이 구성하였습니다.
```
#!/bin/bash
set -e
cd ~/OSVS/kafl

# 컴파일
x86_64-w64-mingw32-gcc -o test_agent.exe test_agent.c \
    -I ~/OSVS/kafl/kAFL/kafl/examples/ -static

# 오버레이 새로 만들기
rm -f overlay.qcow2
qemu-img create -f qcow2 -b Win11.qcow2 -F qcow2 overlay.qcow2

# 마운트
sudo modprobe nbd max_part=8
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sleep 1
sudo mount -t ntfs-3g /dev/nbd0p3 /mnt/win

# 에이전트 주입
sudo cp test_agent.exe "/mnt/win/Users/user/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"

# 확인
echo "Injected files:"
sudo ls "/mnt/win/Users/user/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"

# 정리
sudo umount /mnt/win
sudo qemu-nbd --disconnect /dev/nbd0

echo "Done!"                          
```

### 퍼저 실행
seed 폴더를 만들고 `input_0`이라는 이름의 raw data를 만들어 AAAA 값을 넣어줍니다.

그 후 run.sh를 다음과 같이 구성하면 제일 기초적인 퍼징을 수행할 수 있습니다. 상세한 경로는 각자 환경에 맞게 고쳐쓰시면 될 거 같습니다.
```
kafl fuzz \
    --purge \
    -w /tmp/kafl_test \
    --seed-dir ~/OSVS/kafl/seed/ \
    --memory 4096 \
    --image ~/OSVS/kafl/overlay.qcow2 \
    --redqueen \
    --qemu-extra="-drive if=pflash,format=raw,readonly=on,file=$HOME/OSVS/kafl/OVMF_CODE.fd -drive if=pflash,format=raw,file=$HOME/OSVS/kafl/OVMF_VARS.fd"
```

퍼징 수행 화면은 대충 다음과 같습니다. <br>

![k6](/assets/img/posts/Study/kafl_6.png) <br>

