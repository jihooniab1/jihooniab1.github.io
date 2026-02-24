---
title: "Intel Virtualization Technology"
date: 2026-02-24 00:00:00 +0900
categories: [Papers]
tags: [OS, virtualization]
permalink: /posts/Intel-Virtualization/
math: true
---

# Summary for Intel Virtualization Technology

`2005년에 나온 paper라 이때는 Itanium 아키텍처가 64비트를 대표하는 아키텍처였습니다. 지금은 사장되고 x86_64만 사용되고 있으니 Vt-i, Itanium 관련 내용은 중요하지 않다고 간주하여 제외하였습니다.`

가상화가 없는 시스템에서는 단일 OS가 모든 하드웨어 플랫폼 자원을 관리하는 것에 비해, 가상화 시스템은 새로운 소프트웨어 계층인 **virtual machine monitor** 를 도입합니다. VMM의 핵심 역할은 **물리 호스트 플랫폼 자원에 대한 접근을 중재(arbitrate)** 하여 VMM의 게스트들이 이를 공유할 수 있도록 하는 것입니다. VMM은 각 게스트 OS에게 가상의 하드웨어처럼 보이는 인터페이스를 제공합니다. 즉, VM이란 VMM이 게스트에게 제공하는 하드웨어 추상화 레이어입니다. 하이엔드 서버나 메인프레임에서나 쓰던 가상화가 IA 기반 시스템에 널리 보급된 데는 세 가지 배경이 있습니다. IA 기반 시스템의 성능 향상으로 가상화 오버헤드가 완화된 점, 기존 IA 가상화의 어려움을 해결하는 새로운 소프트웨어 기법의 등장, 그리고 산업계와 학계에서 가상화의 새로운 활용 사례가 부각된 점입니다.

## Virtualization Usage Models
![i1](/assets/img/posts/papers/intel_virt_1.png) <br>

기존에는 메인프레임 시스템에서의 활용도 향상, 관리 편의성, 안정성이 가상화의 주요 장점으로 여겨졌습니다. 서로 다른 OS 환경이 필요한 여러 사용자가 가상화된 서버를 손쉽게 공유할 수 있으며, OS 업그레이드를 VM 단위로 순차적으로 진행하여 다운타임을 최소화할 수 있고, 게스트 소프트웨어에서 장애가 발생하더라도 해당 VM 내부로 격리되어 다른 VM에 영향을 주지 않습니다. 최근 학술 연구와 새로운 VMM 기반 제품들이 등장하면서, 위 그림과 같이 이러한 장점들이 하이엔드 서버뿐만 아니라 서버와 클라이언트 전반에 걸쳐 더 넓은 범위로 활용될 수 있음이 제안되고 있습니다.

### Workload isolation
가상화 기술은 **각 VM에 독립적인 소프트웨어 환경을 격리시켜** 한 VM에서 문제가 생겨도 다른 VM에 영향을 끼치지 않도록 하여 시스템의 보안과 안정성을 향상시킬 수 있습니다. 시스템-소프트웨어 격리 철학은 마이크로소프트의 NGSCB (Next-Generation Secure Computing Base), VMware의 ACE(Assured Computing Environment)에 잘 드러나있습니다. 

### Workload consolidation
기업 데이터 센터들은 급증하는 이기종(heterogeneous)의 활용도가 낮은 서버들 때문에 문제를 겪고 있었습니다. 이러한 서버들은 웹 호스팅이나 파일 서빙처럼 단일 OS·단일 애플리케이션 용도로만 쓰이면서 물리 서버를 하나씩 독점했습니다. 가상화를 통해 **이러한 작업들을 단일 물리 플랫폼으로 통합** 하면 비용을 낮출 수 있었습니다.

새로운 하드웨어나 OS 업그레이드를 할 때도 가상화를 통해 시스템에서 legacy OS와 새로운 OS를 동시에 실행하며 업그레이드를 진행할 수 있습니다. 

특정 시스템 관리 기능을 VM 안에 내장할 수도 있습니다. 예를 들어 모든 네트워크 트래픽을 management VM을 통해 라우팅하면, 클라이언트가 바이러스에 감염된 것으로 판단될 때 자동으로 인트라넷에서 차단하는 "네트워크 차단기" 기능을 구현할 수 있습니다.

### Workload migration
게스트의 VM 상태를 캡슐화하여 하드웨어로부터 분리할 수 있다면, 다른 플랫폼으로도 옮길 수 있게 됩니다. 하드웨어 유지보수 외에도 VM migration을 통해 특정 서버에 부하가 몰리면 자동으로 VM을 분산하는 workload balancing, 서버가 고장날 것 같으면 VM을 미리 옮기는 작업도 할 수 있게 됩니다. 이를 통해 더 낮은 운영 비용으로 더 나은 서비스 품질을 제공할 수 있으며 VMware의 VMotion 같은 상용 제품의 기반이 되었습니다.

## Software-only Intel Architecture Virtualization
점점 많은 애플리케이션들이 서버와 클라이언트 시스템 모두에서 가상화에 대한 강력한 지원을 필요로 하고 있는데, IA-32 아키텍처는 이러한 지원을 구현하는 데 많은 어려움을 야기합니다. 이러한 어려움들 중 일부는 소프트웨어적 기법으로 해결할 수 있습니다.

### Challenges to virtualizing Intel architectures
![i2](/assets/img/posts/papers/intel_virt_2.png) <br>

Intel 마이크로프로세서는 2-bit 권한 레벨 개념을 이용하여, 제일 권한이 높은 특권 소프트웨어에게는 0, 제일 낮은 소프트웨어에게는 3을 사용합니다. 권한 레벨은 CPU를 제어하는 privileged instruction을 폴트 없이 실행할 수 있는지 결정할 때 사용되고, 프로세스의 페이지 테이블이나 IA-32비트에서의 세그먼트 레지스터에 기반하여 주소 공간 접근 가능 여부를 결정할 때도 사용됩니다. 위 그림에서 나와있듯이 대부분 IA 소프트웨어는 0과 3만을 사용합니다.

OS가 CPU를 제어하기 위해서는 특정 요소들은 권한 레벨 0에서 작동해야 합니다. VMM은 게스트 OS이 권한 레벨 0에서 작동하지 못하도록 **ring deprivileging** 을 사용하여 모든 게스트들이 권한 레벨 0보다 낮은(1 이상) 권한을 갖고 동작하게 합니다. 게스트에게 권한 레벨 1을 부여하는 (0/1/3) 모델과 3을 부여하는 (0/3/3) 모델이 있습니다. 0/1/3 모델이 더 단순해보이지만, `Intel EM64T (Extended Memory 64 Technology)`를 지원하는 CPU에서는 64비트 모드에 0, 3 레벨만 존재하여 64비트 게스트를 올릴 때 0/1/3 모델을 사용할 수가 없습니다.

#### Ring aliasing
**Ring aliasing** 문제는 **소프트웨어가 작성되었을 때의 레벨과 다른 권한 레벨에서 작동** 하고 있을 때 발생합니다. 예를 들어 IA-32에서 PUSH 명령어를 들 수 있습니다. PUSH 명령어는 연산자를 스택에 push하는 역할을 하는데, CS 레지스터를 피연산자로 실행하면 CS에 포함된 현재 권한 레벨이 스택에 그대로 노출되어 게스트 OS가 자신이 ring 0이 아님을 알 수 있습니다. 

#### Address-space compression
OS는 IA-32에서 선형주소라고 부르는 프로세서의 전체 가상 주소 공간에 접근할 수 있습니다. 그런데 VMM은 게스트의 가상 주소 공간 일부를 자신의 코드와 자료 구조를 위해 차지해야 합니다. VMM이 별도의 주소 공간에서 실행되는 경우에도, 게스트와 VMM 사이의 전환을 처리하기 위한 제어 구조체를 위해 게스트 가상 주소 공간의 일부를 사용해야 합니다. IA-32에서는 이러한 자료구조에 GDT, IDT가 포함되어 있습니다.

VMM은 자신이 사용하는 영역에 게스트가 접근하지 못하도록 보호해야 합니다. 게스트가 해당 영역에 쓰기를 시도하면 VMM 무결성이 훼손될 수 있고, 읽기를 시도하면 자신이 가상화된 환경에서 실행 중임을 알 수 있기 때문입니다. **address-space compression** 문제는 이렇게 VMM이 차지한 영역을 보호하면서도 게스트의 접근 시도를 적절히 에뮬레이션하여 VMM이 대신 처리하도록 하는 어려움을 의미합니다. 

#### Nonfaulting access to privileged state
권한 기반 보호 기법은 권한이 부족한 소프트웨어가 CPU의 특권 상태(CR0, GDTR, IDTR 등)에 접근하는 것을 방지합니다. 대부분의 경우 접근 시도는 fault로 이어지고 VMM이 이를 에뮬레이트합니다. 그러나 IA-32 아키텍처에는 권한이 부족한 상태에서 특권 상태에 접근해도 fault를 일으키지 않는 명령어가 있습니다. IA-32 레지스터인 GDTR, IDTR, LDTR, TR은 CPU 동작을 제어하는 자료구조의 base address와 limit를 담고 있습니다. 소프트웨어는 권한 레벨 0에서만 이 레지스터들에 쓰기(LGDT, LIDT 등)를 할 수 있지만, 읽기(SGDT, SIDT 등)는 어떤 권한 레벨에서도 가능합니다. VMM이 이 레지스터들의 값을 예상과 다르게 관리하고 있다면 게스트 OS가 자신이 CPU를 온전히 제어하지 못한다는 것을 알아챌 수 있습니다.

#### Adverse impacts on guest transitions(guest app -> guest OS)
Ring deprivileging은 IA-32 아키텍처에서 OS 소프트웨어로의 전환을 빠르게 처리하도록 설계된 메커니즘들의 **효율성을 저하** 시킬 수 있습니다. 예를 들어 IA-32의 SYSENTER와 SYSEXIT 명령어는 기존의 `int` 명령어보다 낮은 레이턴시로 시스템 콜을 처리하도록 설계되었습니다. SYSENTER는 x86_64의 `syscall`을 생각하면 됩니다. Ring deprivileging이 도입되면 게스트 애플리케이션이 SYSENTER를 실행했을 때 게스트 OS가 아니라 VMM으로 전환되고, VMM이 모든 SYSENTER를 에뮬레이트해야 합니다. 게스트 OS가 SYSEXIT를 실행했을 때도 VMM으로 fault가 발생하며 VMM이 에뮬레이트해야 합니다. 

#### Interrupt virtualization
외부 인터럽트, 특히 인터럽트 마스킹에 대한 지원은 VMM 설계에 특수한 어려움을 야기합니다. 인터럽트 마스킹은 **OS가 준비되지 않았을 때 인터럽트 전달을 막는 메커니즘** 으로 IA-32에서는 EFLAGS 레지스터의 **interrupt flag (IF)** 를 사용하여 인터럽트 마스킹을 제어합니다. VMM은 게스트가 인터럽트 마스킹을 직접 제어하지 못하도록 막아야 하는데, ring deprivileging 환경에서는 게스트가 EFLAGS.IF를 건드릴 대마다 fault가 발생해서 VMM이 가로챌 수 있습니다. 이때 모든 마스킹/언마스킹을 가로채면 심각한 성능저하가 발생하고, 가로채지 않으면 게스트에게 가상 인터럽트를 전달하고 싶을 때 게스트가 언마스킹 하는 순간을 놓칠 수 있게 됩니다. 

#### Ring compression
IA-32 페이징은 ring 0-2를 구분하지 않기 때문에, 64비트 모드에서는 페이징만으로 보호를 해야 하는데 게스트 OS를 ring 1에 올릴 수가 없어서 ring 3에 올려야 합니다. 이렇게 되면 게스트 OS와 게스트 앱이 둘 다 ring 3에서 실행되어 게스트 OS가 앱으로부터 자신을 보호할 수 없게 됩니다. 이 문제를 **ring compression** 이라고 합니다.

#### Access to hidden state
일부 CPU 상태는 소프트웨어로 접근할 수 있는 레지스터에 존재하지 않습니다. 예를 들어 **세그먼트 레지스터의 descriptor cache** 가 있는데, 세그먼트 레지스터를 로드하면 GDT/LDT에서 디스크립터를 읽어 CPU 내부 캐시에 저장합니다. 이후 GDT/LDT를 수정해도 캐시는 그대로 유지되며, 소프트웨어로 직접 읽거나 쓸 수 없습니다. VM을 저장하고 복원할 때 이러한 hidden state를 저장/복원할 방법이 없어서 VM 복원 시 오작동이 발생할 수 있습니다. 

### Addressing virtualization challenges in software
이러한 문제들을 해결하기 위해 VMM 디자이너들은 게스트 소프트웨어를 수정하는 **paravirtualization(반가상화)** 기법을 개발하였습니다. 게스트 OS 커널과 디바이스 드라이버를 수정하여 가상화하기 쉬운 인터페이스를 만드는 것입니다. 반가상화는 성능 면에서 우수하고 게스트 애플리케이션들이 수정 없이도 실행될 수 있지만, 운영체제 자체가 반가상화를 지원해야 한다는 단점이 있습니다. 반가상화를 지원하지 않는 legacy OS도 지원하는 VMM들이 있었는데, 이러한 VMM들은 게스트 OS 바이너리를 실행 중에 동적으로 스캔하여 문제가 되는 명령어를 안전한 코드로 교체하는 **binary translation** 을 사용했습니다.

Intel Virtualization Technology의 핵심 목표는 CPU 반가상화와 바이너리 변환을 하지 않아도 되도록 하면서, 높은 가상화 성능을 유지하는 것입니다.

## Intel Virtualization Technology(VT-x)
VT-x는 IA-32 아키텍처에 2개의 새로운 CPU 연산 모드를 추가합니다.

1. VMX root operation
2. VMX non-root operation

VMM은 VMX root operation으로 실행되고 게스트들은 VMX non-root operation으로 실행됩니다. 둘 다 모든 권한 레벨을 지원하기에 게스트 OS는 의도된 권한 레벨에서 동작할 수 있고, VMM도 ring 0만 사용하는 게 아니라 유연하게 권한 레벨을 활용할 수 있습니다. VMX root operation은 VT-x가 없는 IA-32와 유사하고, VMX non-root operation에서는 권한 레벨과 무관하게 특정 명령어들이 제한되어 VM exit를 트리거합니다.

VT-x는 2개의 새로운 전환을 정의합니다.

1. **VM entry**: VMX root operation → VMX non-root operation (VMM → guest)
2. **VM exit**: VMX non-root operation → VMX root operation (guest → VMM)

**Virtual-machine control structure (VMCS)** 는 VM entry, VM exit, VMX non-root operation 모드에서의 프로세서 동작을 관리하는 자료구조입니다. VMCS는 `guest-state area`와 `host-state area`로 논리적으로 나뉘어져 있으며, VM entry 시 guest-state area에서 프로세서 상태를 불러오고, VM exit 시 프로세서 상태를 guest-state area에 저장한 다음 host-state area에서 불러옵니다.

프로세서가 VMX non-root operation 모드에서 실행 중일 때 많은 명령어들과 이벤트가 VM exit을 트리거합니다. 예를 들어 `CPUID, MOV from CR3, RDMSR, WRMSR` 같은 명령어들은 무조건적으로 VM exit을 발생시킵니다. 다른 명령어나 이벤트는 VMCS의 `VM-execution control field`에서 VM exit을 조건적으로 트리거하도록 설정할 수 있습니다.

### VM-execution control fields
VM-execution control field는 VM exit을 트리거할 명령어와 이벤트를 VMM이 설정할 수 있도록 합니다. `HLT, INVLPG, MOV CR8, MOV DR`과 같은 명령어들에 대해 각각 독립적으로 설정할 수 있으며, `CR0, CR3, CR4`에 대한 보호 여부도 설정할 수 있습니다.

VT-x는 인터럽트 가상화를 지원하는 두 가지 설정 항목을 포함합니다. **external interrupt exiting control** 이 설정되어 있으면 모든 외부 인터럽트가 VM exit을 트리거하고 게스트는 인터럽트 마스킹을 제어할 수 없습니다. **interrupt-window exiting control** 이 설정되어 있다면 게스트가 인터럽트를 받을 준비가 될 때마다 VM exit이 트리거됩니다.

유연성을 위해 VT-x는 일부 VM exit 발생 여부를 비트맵으로 세밀하게 제어할 수 있습니다. `exception bitmap`은 IA-32 예외 32개에 대해 각각 VM exit 여부를 설정할 수 있고, I/O 비트맵은 I/O 명령어에 대해 포트별로 VM exit 여부를 설정할 수 있습니다.

### VMCS details
Guest-state area는 해당 VMCS에 대응하는 가상 CPU의 상태를 저장합니다. CR3, IDTR, 세그먼트 레지스터와 같이 프로세서 연산을 관리하는 IA-32 레지스터 필드들도 포함됩니다. VM이 중단되었다가 실행을 재개해도 그 값들을 복구할 수 있도록 세그먼트 레지스터의 `descriptor cache`와 같은 **nonregister processor state** 도 저장됩니다.

VMM은 VMCS를 선형 주소가 아닌 물리 주소로 참조하여 VMCS를 게스트 선형 주소 공간에 위치시키지 않아도 되게 합니다.

### VM entries and exits
`VM entry` 명령은 VMCS의 guest-state area로부터 프로세서 상태를 로드합니다. 