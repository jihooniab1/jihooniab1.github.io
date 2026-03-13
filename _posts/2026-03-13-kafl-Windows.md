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

