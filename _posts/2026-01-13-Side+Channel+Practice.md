---
title: "Side Channel Practice"
date: 2026-01-13 00:00:00 +0900
categories: [Study]
tags: [security, side channel]
permalink: /posts/Side+Channel+Practice/
math: true
---

# 사이드 채널 실습

## Cache
캐시는 더 크고 느린 저장 장치에 있는 **데이터의 일부를 임시로 보관** 하는, 더 작고 빠른 저장 장치입니다. 소프트웨어에게는 보이지 않으며, `load/store` 명령에 반응하여 하드웨어가 알아서 관리합니다. 

데이터 블록 x에 있는 데이터가 필요한데, 만약 블록 x가 캐시에 있다면 **Cache Hit**,  위 그림과 같이 필요한 블락이 캐시에 없다면 **Cache Miss** 로 표현합니다. Cache Miss에는 3가지 유형이 존재하는데, 다음과 같습니다.

1. Cold Miss: 처음 접근하는 블록이라 발생하는 미스로, 캐시가 아무리 커도 피할 수 없습니다(compulsory).
2. Capacity Miss: 현재 사용 중인 데이터가 캐시보다 클 때 발생합니다. 캐시 크기가 작아서 발생하는 미스입니다. 
3. Conflict Miss: 같은 위치에 여러 데이터가 매핑되어서 발생하는 미스로, **배치 정책(Placement Policy)** 때문에 특정 위치에만 데이터를 넣을 수 있을 때 발생합니다. 

![s2](/assets/img/posts/Study/side_prac_2.png) <br>

위 그림은 캐시의 전체적인 구조를 나타내고 있습니다. **S, E, B** 는 세 가지 핵심 파라미터입니다. 
- S: $2^s$ sets, 캐시에 있는 세트의 개수를 나타냅니다.
- E: $2^e$ lines per set, 각 세트 안에 있는 라인(블록) 개수입니다.
- B: $2^b$ bytes per block, 각 블록의 크기, 즉 실제 데이터의 크기입니다. 블록은 캐시가 한 번에 가져오는 데이터 단위를 의미합니다. 캐시 라인은 `블록 전체`에 **valid bit + tag까지 합쳐진** 구조입니다.

캐시 용량은 S x E x B로 계산할 수 있습니다.

오른쪽 부분은 메모리 주소를 **세 부분으로** 쪼개는 방식입니다. 
- tag(t bits): 찾고 있는 블록이 맞는지 확인할 때 사용합니다.
- set index(s bits): 원하는 블록이 어느 세트에 있는지 찾을 때 사용합니다.
- block offset(b bits): 블록 안에서 몇 번째 바이트인지를 나타냅니다.

캐시에 접근을 할 때 먼저 주소에서 **set index** 로 세트를 찾은 다음, 그 세트안의 모든 라인에서 **tag** 를 비교하고, tag가 일치하고 **valid bit** 가 1이라면 cache hit가 발생하는 것입니다. 또한 다음과 같은 공식이 항상 성립하기에 t가 어떻게 결정되는지 파악할 수 있습니다.

```
m = t + s + b
```
- m: 아키텍처 주소 크기
- s, b -> 캐시 설계 때 정해짐(세트 수, 블록 크기)

주소 공간의 모든 주소가 캐시에 매핑될 수 있도록 tag의 길이가 정해집니다. t(tag)가 e(세트 당 라인 수)보다 크다면, 여러 블록이 한 라인을 두고 경쟁하는 관계라고 보면 됩니다.  

### Direct-Mapped Cache
Direct mapped cache는 `E=1`인 경우로 **세트 당 캐시 라인이 1개** 있습니다. 이 구조에서는 주소에 따라 캐시에 들어갈 곳이 정해져 있습니다. <br>

![s3](/assets/img/posts/Study/side_prac_3.png) <br>

위 그림에서 세트 수 비트 `s = 10`이고 `b = 2`, 즉 블록의 크기가 4바이트입니다. 주소의 크기 `m = 64`이므로 태그의 길이 `t = 52`가 됩니다. 10 비트 길이의 s로 캐시 세트를 식별하고, valid bit와 tag를 통해 cache hit 유무를 확인하는 것을 볼 수 있습니다. Cache hit이 발생하면 그대로 그 값을 반환하지만, cache miss가 발생하면 이전 라인은 **축출(evict), 교체(replace)** 됩니다.

구조가 단순하고 탐색이 빠르다는 장점이 있으나, **conflict miss(같은 세트에 매핑되는 주소들이 경쟁)** 가 자주 발생할 수 있습니다. 

### E-way Set Associative Cache
![s4](/assets/img/posts/Study/side_prac_4.png) <br>
유연한 블록 배치를 통해 **Miss rate** 를 줄이는 방법입니다. 이전의 direct-mapped cache에서는 블록을 **한 곳에만** 넣을 수 있도록 하는 방법이었다면, fully-associative 구조는 캐시의 **어느 곳에나** 들어갈 수 있도록 하는 방법입니다. 둘을 절충하여 각 블록당 `n개`의 배치 가능한 위치를 갖는 set associative 캐시를 **n-way set associative** 캐시라고 부릅니다. 이 구조에서는 블록이 캐시 세트 집합 어느 곳에나 존재할 수 있기 때문에 **집합 내의 모든 블록의 태그를 검사** 해야 합니다. Associativity를 늘리는 것의 장점은 `miss rate`가 줄어드는 것이고, 단점은 `hit time`이 늘어나는 것입니다. 

만약 cache miss가 발생하면 세트에 있는 캐시 라인 중 하나가 선택되어 교체되어야 합니다. 이때 사용되는 **교체 정책(Replacement policies)** 에는 여러가지가 있지만, 널리 사용되는 방식으로는 **LRU(Least Recently Used)** 가 있습니다. 가장 오랫동안 사용되지 않은 블럭을 교체하는 방식입니다. 

### VIPT(Virtually Indexed, Physically Tagged)
![s6](/assets/img/posts/Study/side_prac_6.png) <br>
L1 캐시는 속도가 가장 중요합니다. 사이클 하나하나가 critical 하기 때문에 **TLB** 과정을 기다리는 시간조차 소중합니다. VIPT는 현대 아키텍처에서 L1 캐시에 한해서는 대부분 사용하는 구조로 핵심은 **TLB 조회와 캐시 인덱싱을 동시에 하는 것** 입니다. 위에서 다뤘던 공식인 `m = t + s + b`를 다시 확인해봅시다. b는 그냥 6이라고 하고 지나갑시다. 이론적으로는 VA -> PA -> 캐시 인덱싱의 과정으로 진행이 되어야 하지만, 굳이 이렇게 하지 말고 인덱스 비트 수를 6 이하로 맞춰 **s + b <= 12** 가 되도록 하는 것이 핵심입니다. 캐시는 무조건 물리 주소를 갖고 찾아야 하는데, 어차피 가상 주소의 12비트와 물리 주소의 12 비트는 **페이지 오프셋** 으로 동일하기 때문에, 하위 12비트는 그대로 써도 됩니다. s + b = 12라면 s가 6, 즉 캐시 세트가 64개라는 뜻이며, 이렇게 되면 TLB 조회를 기다리지 않고 캐시의 세트부터 바로 검색을 할 수 있습니다. 캐시의 세트를 찾은 다음에 TLB나 PTE를 조회하여 얻은 물리 주소인 캐시 태그를 갖고 way를 찾는 방식입니다.

그런데 만약 캐시의 설계가 `s + b > 12` 상황일 때 VIPT를 사용하려고 하면 **cache aliasing** 문제가 발생합니다. way를 늘리면 mux가 많이 필요해 비용이 늘어나, 캐시 크기를 늘리면서 way를 줄이기 위해 **세트 수는 256($2^8$)개** 이고 2-way인 캐시를 생각해봅시다. 이렇게 되면 캐시 인덱싱을 할 때 총 14비트가 필요하게 되는데, 변하지 않는 페이지 오프셋은 여전히 12바이트입니다. 이 경우 부족한 2비트는 가상 주소에 있는걸 그대로 갖다 쓰는데, 이 경우 2비트의 차이로 인해 **사실은 동일한 물리 주소가 서로 다른 캐시 세트에 여러번 매핑** 되는 Aliasing이 발생하게 됩니다. 

이 문제를 해결하는 방법은 여러가지가 있습니다. 먼저 OS 레벨에서 사용하는 **Page Coloring** 이라는 방식이 있습니다. 이 방식은 OS가 메모리를 할당하고 가상 주소와 물리 주소를 매핑할 때마다, 두 주소의 하위 18비트(인덱싱 비트)가 일치되게 하는 것입니다. 캐시 측면에서 이 방법은 **페이지 오프셋** 을 증가시키는 효과를 갖고 있으며, 이를 통해 유사 VIPT 방식을 사용할 수 있게 됩니다. 그러나 page coloring은 메모리를 있어도 할당을 못하는 **단편화** 문제나 메모리를 줄 때마다 색깔이 맞는지 검사를 해야 하는 오버헤드 문제가 존재하기 때문에 cache miss가 발생할 때마다 바로 로드하지 않고, 먼저 가능한 set 위치를 모두 탐색해서 물리 주소가 캐시 어딘가에 올라가 있는건 아닌지 하드웨어적으로 체크를 하는 방법을 사용하기도 합니다(예: ARM의 Cortex-A53). 

## Hardware spec
실습을 진행할 노트북의 상세한 스펙은 다음과 같습니다. `lscpu` 명령어는 리눅스에서 CPU 정보를 보여주는 명령어로 터미널에 입력하면 됩니다.

```
user@Ubuntu:~/Private/jihooniab1.github.io$ lscpu
Architecture:                x86_64
  CPU op-mode(s):            32-bit, 64-bit
  Address sizes:             46 bits physical, 48 bits virtual
  Byte Order:                Little Endian
CPU(s):                      22
  On-line CPU(s) list:       0-21
Vendor ID:                   GenuineIntel
  Model name:                Intel(R) Core(TM) Ultra 7 155H
    CPU family:              6
    Model:                   170
    Thread(s) per core:      2
    Core(s) per socket:      16
    Socket(s):               1
    Stepping:                4
    CPU(s) scaling MHz:      25%
    CPU max MHz:             4800.0000
    CPU min MHz:             400.0000
    BogoMIPS:                5990.40
    Flags:                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb intel_pt sha_ni xsaveopt xsavec xgetbv1 xsaves split_lock_detect user_shstk avx_vnni dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp hwp_pkg_req hfi vnmi umip pku ospke waitpkg gfni vaes vpclmulqdq rdpid bus_lock_detect movdiri movdir64b fsrm md_clear serialize arch_lbr ibt flush_l1d arch_capabilities

Caches (sum of all):         
  L1d:                       544 KiB (14 instances)
  L1i:                       896 KiB (14 instances)
  L2:                        18 MiB (9 instances)
  L3:                        24 MiB (1 instance)
...
```

대충 이런 식으로 뜨는데 정리해보면 다음과 같습니다.

- 아키텍처: x86_64
- CPU: Intel Core Ultra 7 155H (Meteor Lake)
- 물리코어: 16
- 논리 프로세서: 22
- 소켓: 1개

캐시의 경우 Intel 공식 문서(https://edc.intel.com/content/www/jp/ja/design/products/platforms/details/meteor-lake-u-p/core-ultra-processor-datasheet-volume-1-of-2/p-core-e-core-and-lp-e-core-level-1-and-level-2-caches/)에서 캐시 구조에 대한 설명을 확인할 수 있습니다. <br>

![s5](/assets/img/posts/Study/side_prac_5.png) <br>

위 그림은 Meteor Lake 프로세서의 **P-core, E-core, and LP E-core Cache Hierachy** 입니다. P-코어는 Performance Core로 고성능 코어입니다. 각각 자체 L2 캐시와 DL1(데이터 L1, 48KB, 12-way), IL1(명령어 L1, 64KB, 16-way) 캐시를 갖고 있습니다. E-코어는 Efficiency Core로 저전력 효율 코어입니다. 여러 개의 E-코어가 하나의 모듈로 묶여 L2 캐시를 공유하며, 각 코어는 개별 DL1(32KB, 8-way)과 IL1(64KB, 16-way) 캐시를 보유합니다. P-코어와 E-코어는 모두 Compute Tile에 위치하며, **LLC(Last Level Cache)를 공유** 합니다. LP E-코어는 별도로 배치된 초저전력 코어로 L2 캐시를 공유합니다.

그래서 캐시 인스턴스의 경우 L1D, L1i는 P-코어 6개 + E-코어 8개로 총 `14개`, L2는 P-코어 6개, E-코어 클러스터 2개, LP E 코어 1개로 총 `9개`, L3는 P-코어와 E-코어가 공유하는 24MB 크기의 1개가 있습니다. 아래와 같이 리눅스에서는 커널에서도 캐시 관련 정보를 제공해주기 때문에 이를 참고할 수도 있습니다. 실제로 확인해보면 명세와 똑같습니다.

```
user@Ubuntu:/sys/devices/system/cpu/cpu0/cache/index0$ grep . /sys/devices/system/cpu/cpu0/cache/index3/*
/sys/devices/system/cpu/cpu0/cache/index3/coherency_line_size:64
/sys/devices/system/cpu/cpu0/cache/index3/id:0
/sys/devices/system/cpu/cpu0/cache/index3/level:3
/sys/devices/system/cpu/cpu0/cache/index3/number_of_sets:32768
/sys/devices/system/cpu/cpu0/cache/index3/physical_line_partition:1
/sys/devices/system/cpu/cpu0/cache/index3/shared_cpu_list:0-19
/sys/devices/system/cpu/cpu0/cache/index3/shared_cpu_map:0fffff
/sys/devices/system/cpu/cpu0/cache/index3/size:24576K
/sys/devices/system/cpu/cpu0/cache/index3/type:Unified
/sys/devices/system/cpu/cpu0/cache/index3/ways_of_associativity:12
```

## FLUSH+RELOAD
lscpu의 플래그 정보를 보면 아래와 같이 FLUSH+RELOAD 공격에 필요한 플래그들이 있음을 알 수 있습니다.
```
clflush
clflushopt
rdtscp
constant_tsc
nonstop_tsc
```

본 공격은 LLC 캐시를 수행하기 때문에 L3 캐시를 공유해야 하는데, 논리 코어 22개 중 0번부터 19번까지 P-코어와 E-코어에 배치되어있습니다.
```
user@Ubuntu:~$ cat /sys/devices/cpu_core/cpus
0-11
user@Ubuntu:~$ cat /sys/devices/cpu_atom/cpus
12-21
```

다만 변수가 될 수 있는 부분은 `Intel Smart Cache Technology` 문서에서 **The LLC is non-inclusive** 라고 밝히고 있어 이 점이 FLUSH+RELOAD 공격을 수행하는데 방해가 될 수도 있습니다. 

FLUSH+RELOAD 공격을 재현해보려면, 제일 먼저 spy와 victim 사이의 물리 페이지 공유가 이뤄져야 합니다. 리눅스에서는 `/proc/pid/pagemap` 파일을 통해 **가상주소 -> 물리주소** 변환 정보를 제공하고 있습니다. 먼저 `/proc/pid/maps` 파일을 확인해보면, 마치 디버거에서 vmmap을 하는 거 같은 결과를 볼 수 있습니다.
```
user@Ubuntu:~/css/flush-reload-attacks$ sudo cat /proc/173056/maps
00400000-00401000 r--p 00000000 103:04 19570708                          /home/user/css/flush-reload-attacks/l1_victim_simple
00401000-00402000 r-xp 00001000 103:04 19570708                          /home/user/css/flush-reload-attacks/l1_victim_simple
00402000-00403000 r--p 00002000 103:04 19570708                          /home/user/css/flush-reload-attacks/l1_victim_simple
00403000-00404000 r--p 00002000 103:04 19570708                          /home/user/css/flush-reload-attacks/l1_victim_simple
00404000-00405000 rw-p 00003000 103:04 19570708                          /home/user/css/flush-reload-attacks/l1_victim_simple
0f78b000-0f7ac000 rw-p 00000000 00:00 0                                  [heap]
717940200000-717940228000 r--p 00000000 103:04 20580768                  /usr/lib/x86_64-linux-gnu/libc.so.6
717940228000-7179403b0000 r-xp 00028000 103:04 20580768                  /usr/lib/x86_64-linux-gnu/libc.so.6
7179403b0000-7179403ff000 r--p 001b0000 103:04 20580768                  /usr/lib/x86_64-linux-gnu/libc.so.6
7179403ff000-717940403000 r--p 001fe000 103:04 20580768                  /usr/lib/x86_64-linux-gnu/libc.so.6
717940403000-717940405000 rw-p 00202000 103:04 20580768                  /usr/lib/x86_64-linux-gnu/libc.so.6
717940405000-717940412000 rw-p 00000000 00:00 0 
717940572000-717940575000 rw-p 00000000 00:00 0 
71794058d000-71794058f000 rw-p 00000000 00:00 0 
71794058f000-717940591000 r--p 00000000 00:00 0                          [vvar]
717940591000-717940593000 r--p 00000000 00:00 0                          [vvar_vclock]
717940593000-717940595000 r-xp 00000000 00:00 0                          [vdso]
717940595000-717940596000 r--p 00000000 103:04 20580765                  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
717940596000-7179405c1000 r-xp 00001000 103:04 20580765                  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7179405c1000-7179405cb000 r--p 0002c000 103:04 20580765                  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7179405cb000-7179405cd000 r--p 00036000 103:04 20580765                  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7179405cd000-7179405cf000 rw-p 00038000 103:04 20580765                  /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffe86c90000-7ffe86cb1000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

페이지의 크기는 4KB이며, 위의 결과에서 각 주소 범위들은 전부 0x1000 크기의 페이지들로 구성되어 있다고 보면 됩니다. 아래 표와 같이 `pagemap` 파일을 룩업 테이블처럼 활용하여 가상 주소와 매핑 되어 있는 실제 물리 페이지 엔트리 넘버와 오프셋, 상태 등을 알아낼 수 있습니다. 

| Page | Virtual Addr | Permission    | Status       | Phys Addr     |
|------|--------------|---------------|--------------|---------------|
|  1   | 0x400000   | r--p (Header) | Present      | 0x3e16e7000   |
|  2   | 0x401000   | r-xp (CODE)   | Present      | 0x465701000   |
|  3   | 0x402000   | r--p (RODATA) | Present      | 0x2927bb000   |
|  4   | 0x403000   | r--p (RODATA) | Present      | 0x1f537d000   |
|  5   | 0x404000   | rw-p (DATA)   | Present      | 0x444a0a000   |

이제 이러한 점들을 이용하여, 먼저 자신이 매핑되어 있는 물리 페이지 주소를 반환하는 C 코드를 작성해보겠습니다. 

```c
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

uint64_t get_physical_addr(void *vaddr) {
    
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        perror("open /proc/self/pagemap");
        return 0;
    }

    unsigned long page_size = getpagesize();
    unsigned long offset = ((unsigned long)vaddr / page_size) * sizeof(uint64_t);

    uint64_t entry;
    if (pread(fd, &entry, sizeof(entry), offset) != sizeof(entry)) {
        perror("pread");
        close(fd);
        return 0;
    }
    close(fd);

    // Bit 63: 페이지가 RAM에 있는지 여부를 나타냄
    if (!(entry & (1ULL << 63))) {
        printf("페이지가 메모리에 없습니다\n");
        return 0;
    }

    // Bit 0-54: PFN (Page Frame Number)
    uint64_t pfn = entry & ((1ULL << 55) - 1);

    // 물리 주소 = (PFN * 페이지크기, 보통은 0x1000) + 페이지 내 오프셋
    uint64_t phys_addr = (pfn * page_size) + ((unsigned long)vaddr % page_size);

    return phys_addr;
}

int main() {
    int var1 = 42;

    printf("var1 phy: 0x%lx\n\n", get_physical_addr(&var1));
    printf("main phy: 0x%lx\n", get_physical_addr((void*)main));

    return 0;
}
```

위 코드는 `var1` 변수와 `main` 함수가 실제 물리 주소 상으로는 어느 주소에 위치하는지 찾는 코드입니다. Pagemap 역시 하나의 파일이므로, open을 통해 실행중인 **자기 자신의 페이지 테이블 정보** 를 담고 있는 파일을 준비합니다. 보통 페이지 크기는 4KB지만 확실하게 하기 위해 `getpagesize()` 함수를 호출하여 페이지 크기를 구해준 다음, `vaddr / page_size`를 통해 **VPN** 을 구해줍니다. VPN을 구해준 다음 페이지 엔트리의 크기인 **8바이트** 를 곱해주어야 합니다. Pagemap 파일은 페이지 엔트리 하나 당 아래와 같이 `8바이트`의 정보를 포함하기 때문에 페이지번호에 8을 곱해줘야 합니다.

```
There are four components to pagemap:

 * /proc/pid/pagemap.  This file lets a userspace process find out which
   physical frame each virtual page is mapped to.  It contains one 64-bit
   value for each virtual page, containing the following data (from
   fs/proc/task_mmu.c, above pagemap_read):

    * Bits 0-54  page frame number (PFN) if present
    * Bits 0-4   swap type if swapped
    * Bits 5-54  swap offset if swapped
    * Bit  55    pte is soft-dirty (see Documentation/vm/soft-dirty.txt)
    * Bit  56    page exclusively mapped (since 4.2)
    * Bits 57-60 zero
    * Bit  61    page is file-page or shared-anon (since 3.5)
    * Bit  62    page swapped
    * Bit  63    page present
```

위의 비트 대로 비트들을 확인하여 스왑되었는지, 파일에 매핑된 페이지(61비트)인지 여부 등을 확인한 다음 **PFN** 번호를 얻고 오프셋을 더해주면 됩니다. 
```
user@Ubuntu:~/css/flush-reload-attacks$ sudo ./test
var1 phy: 0x29ae62a84

main phy: 0x42b49c35e
```

이제 spy 프로세스가 victim의 실행 파일을 **mmap** 하였을 때 실제로 같은 물리 주소가 주어지는지 확인해야합니다. Victim 바이너리를 실행하고 있는 상태에서, spy 프로세스가 victim 바이너리를 mmap 하였을 때, 물리 페이지를 그냥 공유해서 주는지 확인하면 됩니다. 

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

// 물리 주소 변환 함수는 똑같음
uint64_t get_physical_addr(void *vaddr) {
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return 0;
    unsigned long page_size = getpagesize();
    unsigned long offset = ((unsigned long)vaddr / page_size) * 8;
    uint64_t entry;
    pread(fd, &entry, 8, offset);
    close(fd);
    uint64_t pfn = entry & ((1ULL << 55) - 1);
    return (pfn * page_size) + ((unsigned long)vaddr % page_size);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <Victim_Binary_Path> <File_Offset_Hex>\n", argv[0]);
        return 1;
    }

    const char *file_path = argv[1];
    unsigned long file_offset = strtoul(argv[2], NULL, 16);

    // victim 바이너리 열기
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    // 파일 전체를 메모리에 매핑, 이때 OS의 페이지 공유가 발생합니다
    void *mapped_base = mmap(NULL, 4096 * 10, PROT_READ, MAP_SHARED, fd, 0);
    if (mapped_base == MAP_FAILED) { perror("mmap"); return 1; }

    // OS의 lazy allocation, demand paging 때문에 mmap하고 실제로 작업을 하지 않으면 물리 페이지를 할당해주지 않습니다
    void *target_ptr = (char *)mapped_base + file_offset;

    volatile char dummy = *(volatile char *)target_ptr;

    uint64_t phys = get_physical_addr(target_ptr);
    printf("phy : 0x%lx", phys);

    return 0;
}
```

원리는 간단합니다. victim 바이너리를 그대로 mmap으로 메모리에 올리면, OS는 메모리 효울성을 높이기 위해 이미 Victim 프로세스에 의해 물리 메모리(RAM)에 로드된 페이지를 새로 복사하지 않고, Spy 프로세스도 그 **똑같은 물리 페이지를 가리키도록 매핑(Page Deduplication)** 해버립니다. `mmap`을 할 때 커널은 fd가 가리키는 파일이 물리 메모리에 이미 올라와 있는지 확인을 하고, 만약 그렇다면 그 PFN을 **spy의 page table** 에도 끼워넣습니다. 주석에도 나와있듯이 mmap만 하고 끝내면 커널이 실제 물리 메모리를 연결해주지 않기 때문에, spy가 주소의 값을 읽으려 시도하면, **CPU의 페이지 폴트** 가 발생하면서 PTE를 채웁니다. 

이제 물리 메모리 페이지가 공유되는 것을 확인했으니 FLUSH+RELOAD 공격을 시도할 수 있습니다. 논문과 똑같이 GnuPG를 victim으로 활용해보겠습니다. 1.4.14 이후 버전은 **Square-and-Multiply-Always** 패치가 적용되어 있으니, 취약한 이전 버전을 대상으로 하겠습니다. `wget https://gnupg.org/ftp/gcrypt/gnupg/gnupg-1.4.13.tar.bz2` 이 링크에서 취약한 버전을 받을 수 있습니다. 

```
./configure \
    CFLAGS="-g -O2 -no-pie -fno-pie -fcommon" \
    LDFLAGS="-no-pie" \
    --disable-asm

make -j$(nproc)
```

위 옵션을 갖고 빌드를 진행했습니다.
- -g: 심볼을 포함
- -O2: 논문과 동일한 최적화 레벨
- -no-pie: PIE 비활성화
- -fno-pie: Position Independent Code 비활성화
- -fcommon: GCC 10부터는 이걸 붙여줘야 `multiple definition` 링커 오류가 방지되는 듯
- --disable-asm: 어셈블리 최적화 끄기

빌드가 완료되면 g10 디렉터리에 gpg 바이너리가 위치하게 됩니다. Probe할 Square, Reduce, Multiply의 경우 다음 함수들의 주소를 사용합니다. 

Square 연산은 **mpih_sqr_n** 함수의 주소를 사용합니다. 아래의 main loop를 확인하면 `rsize < KARATSUBA_THRESHOLD`라는 조건이 있고, 만족하지 못하면 mpih_sqr_n 루틴으로 이어집니다. 
```c
#ifndef KARATSUBA_THRESHOLD
#define KARATSUBA_THRESHOLD 16
#endif
```
이때 16이라는 숫자는 16 limbs를 의미하는데, limb는 단일 CPU 레지스터에 들어가지 않는 크기가 큰 정수를 담는 기본적인 단위라고 보면 됩니다. GnuPG는 키를 둘로 나눠서 계산하기 때문에 initial bsize가 32가 아닌 16 limb이지만, 그래도 여전히 mpih_sqr_n 루틴으로 이어집니다. 그리고 루프를 따라가보면 알 수 있지만 결국 루프가 끝날 때는 다시 크기가 16으로 돌아오므로 Square 연산에 대한 probe는 mpih_sqr_n 함수의 주소로 잡으면 됩니다. 

Multiply 연산의 경우 **mul_n** 함수의 주소를 사용합니다. 루프를 보면 곱셈 연산을 할 때 `mpihelp_mul_karatsuba_case` 함수가 호출되는 것을 알 수 있습니다. 
```c
void
mpihelp_mul_karatsuba_case( mpi_ptr_t prodp,
			    mpi_ptr_t up, mpi_size_t usize,
			    mpi_ptr_t vp, mpi_size_t vsize,
			    struct karatsuba_ctx *ctx )
{
    mpi_limb_t cy;

    if( !ctx->tspace || ctx->tspace_size < vsize ) {
	if( ctx->tspace )
	    mpi_free_limb_space( ctx->tspace );
	ctx->tspace = mpi_alloc_limb_space( 2 * vsize,
				       m_is_secure( up ) || m_is_secure( vp ) );
	ctx->tspace_size = vsize;
    }

    MPN_MUL_N_RECURSE( prodp, up, vp, vsize, ctx->tspace );
```
함수 내부에서 MPN_MUL_N_RECURSE 매크로가 호출됩니다.
```c
#define MPN_MUL_N_RECURSE(prodp, up, vp, size, tspace) \
    do {						\
	if( (size) < KARATSUBA_THRESHOLD )		\
	    mul_n_basecase (prodp, up, vp, size);	\
	else						\
	    mul_n (prodp, up, vp, size, tspace);	\
    } while (0);
```
내부적으로 mul_n이 호출되는데, mul_n 함수 안에도 재귀적 호출을 위해서 똑같은 매크로를 사용하고 있습니다. 

Reduce 연산은 **mpihelp_divrem** 함수의 주소를 사용합니다. 공격의 대상이 되는 main loop는 mpi-pow.c의 182 line에 있습니다.

```c
for(;;) {
    while( c ) {
	mpi_ptr_t tp;
	mpi_size_t xsize;

	/*mpihelp_mul_n(xp, rp, rp, rsize);*/
	if( rsize < KARATSUBA_THRESHOLD )
	    mpih_sqr_n_basecase( xp, rp, rsize );
	else {
	    if( !tspace ) {
		tsize = 2 * rsize;
		tspace = mpi_alloc_limb_space( tsize, 0 );
	    }
	    else if( tsize < (2*rsize) ) {
		mpi_free_limb_space( tspace );
		tsize = 2 * rsize;
		tspace = mpi_alloc_limb_space( tsize, 0 );
	    }
	    mpih_sqr_n( xp, rp, rsize, tspace );
	}

	xsize = 2 * rsize;
	if( xsize > msize ) {
	    mpihelp_divrem(xp + msize, 0, xp, xsize, mp, msize);
	    xsize = msize;
	}

	tp = rp; rp = xp; xp = tp;
	rsize = xsize;

	if( (mpi_limb_signed_t)e < 0 ) {
	    /*mpihelp_mul( xp, rp, rsize, bp, bsize );*/
	    if( bsize < KARATSUBA_THRESHOLD ) {
		mpihelp_mul( xp, rp, rsize, bp, bsize );
	    }
	    else {
		mpihelp_mul_karatsuba_case(
			     xp, rp, rsize, bp, bsize, &karactx );
	    }

	    xsize = rsize + bsize;
	    if( xsize > msize ) {
		mpihelp_divrem(xp + msize, 0, xp, xsize, mp, msize);
		xsize = msize;
	    }

	    tp = rp; rp = xp; xp = tp;
	    rsize = xsize;
	}
	e <<= 1;
	c--;
    }

    i--;
    if( i < 0 )
	break;
    e = ep[i];
    c = BITS_PER_MPI_LIMB;
}
```
루프가 시작하자마자 Square 연산을 무조건 실행 후, `msize`보다 숫자가 커지면 modulo 연산을 하는 부분이 있습니다. 

```c
if( (mpi_limb_signed_t)e < 0 ) {
```
이 조건문이 중요한 분기점입니다. 비트가 1인지 확인하는 조건문으로, **맨 앞 비트가 1인지 여부** 를 확인하는 부분입니다. 그리고 비트가 1일 때만 Multiply 연산이 조건부로 실행이 되는 것을 확인할 수 있습니다. 이제 실제로 gpg 바이너리를 실행해보겠습니다. 

먼저 환경 설정부터 해야합니다. 암호화를 해둬야, 그 파일을 복호화하는 과정을 관측할 수 있기 때문입니다. 

### 1. 키 준비
```
#!/bin/bash                                                                                                                  
# save as: setup-attack.sh                                                                                                   
                                                                                                                               
export GNUPGHOME=/home/user/css/flush-reload-attacks/flush-reload/gpg-test                                                   
export GPG=/home/user/css/flush-reload-attacks/gnupg-1.4.13/g10/gpg          

mkdir -p /home/user/css/flush-reload-attacks/flush-reload/gpg-test
                                                                                                                               
echo "GNUPGHOME=$GNUPGHOME"                                                                                                  
echo "GPG=$GPG"   
```

이런 식으로 배치 파일을 만든 후, 필요할 때 `source ./setup-attack.sh`를 실행합니다. 

### 2. 키 생성
```
user@Ubuntu:~/css/flush-reload-attacks/flush-reload$ $GPG --gen-key
gpg (GnuPG) 1.4.13; Copyright (C) 2012 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
Your selection? 1
RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (2048) 2048
Requested keysize is 2048 bits       
Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 0
Key does not expire at all
Is this correct? (y/N) y
                        
You need a user ID to identify your key; the software constructs the user ID
from the Real Name, Comment and Email Address in this form:
    "Heinrich Heine (Der Dichter) <heinrichh@duesseldorf.de>"

Real name: flush
Email address: flush@reload.kr
Comment:                      
You selected this USER-ID:
    "flush <flush@reload.kr>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o
You need a Passphrase to protect your secret key.    

You don't want a passphrase - this is probably a *bad* idea!
I will do it anyway.  You can change your passphrase at any time,
using this program with the option "--edit-key".
```

이런 식으로 키를 만들어줍니다. Passphrase를 입력하는 부분에서 아무것도 입력하지 않고 엔터만 누르면 됩니다. 

### 3. 실험을 위해서 private key export
```
user@Ubuntu:~/css/flush-reload-attacks/flush-reload$ $GPG --list-secret-keys
/home/user/css/flush-reload-attacks/flush-reload/gpg-test/secring.gpg
---------------------------------------------------------------------
sec   2048R/5402575E 2026-01-20
uid                  flush <flush@reload.kr>
ssb   2048R/C21BA022 2026-01-20
```
먼저 키 ID를 알아내기 위해 키 목록을 확인합니다.

```
$GPG --export-secret-keys --armor flush@reload.kr > $PWD/secret-key.asc
```
그 후 읽을 수 있는 형식으로 private key를 export 해줍니다.

```
pgpdump -i $PWD/secret-key.asc > $PWD/key-dump.txt
```
그리고 실제 **d** 키를 뽑아냅니다. 

```
user@Ubuntu:~/css/flush-reload-attacks/flush-reload$ sed -n '/Secret Subkey Packet/,/Checksum/p' key-dump.txt | grep "RSA d" | cut -d '-' -f 2 | tr -d ' ' > d_hex.txt
user@Ubuntu:~/css/flush-reload-attacks/flush-reload$ cat d_hex.txt 
43765edf321f52a1f886df06f18ce6bfa2f177246eed2cb85694dd2ce867395c3122269ef074ed0703f39e25f1a67f53086f22d219e1b88f6119322758fafddbeae59ef09aa77b204ef6cb97371b59ecae1c57c826860ffc4695522a4a9029320aa7c6f98c9a7041955c72c5d6c885a5f25d16f7bfbec1d24528c69329a1b456f73dd2cbb86c4b34013010ab43e9abd2ddb352169e1cc85f2e59af096a42ceb6b067a2e5cd1a6c1067df2e5dd9281ef369340f3be60bfccc0da08995cdfe3e4b55945c9d882a7ad38cd6d3405d6da4a65780d8002f524cf86f690bb5c8833e8142411bef871ce1ccc34d597c361f869526fdaa8d5b1f343c52026304c39dfbd9
user@Ubuntu:~/css/flush-reload-attacks/flush-reload$ 
```

```
user@Ubuntu:~/css/flush-reload-attacks/flush-reload$ cat dump.py 
import sys
import re

def get_all_params(content, param_name):
    clean_content = re.sub(r'\s+', '', content)
    # findall을 사용하여 모든 키 패킷의 값을 찾음
    pattern = rf"RSA{param_name}\(\d+bits\)-(?P<hex>[0-9a-fA-F]+)"
    matches = re.findall(pattern, clean_content)
    return [int(m, 16) for m in matches]

def main():
    filename = "key-dump.txt"
    
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] {filename} 파일이 없습니다. pgpdump -i ... 명령어를 먼저 실행하세요.")
        sys.exit(1)

    ds = get_all_params(content, "d")
    ps = get_all_params(content, "p")
    qs = get_all_params(content, "q")

    if not ds or not ps or not qs:
        return

    d = ds[-1]
    p = ps[-1]
    q = qs[-1]

    dp = d % (p - 1)
    dq = d % (q - 1)

    dp_bin = bin(dp)[2:]
    dq_bin = bin(dq)[2:]

    print(f"\nTarget Key: Subkey (Encryption Key)")
    print("=" * 60)
    print(f"Calculated dp (d mod p-1) [TOTAL LENGTH: {len(dp_bin)} bits]")
    print("-" * 60)
    print(dp_bin)
    print("\n" + "=" * 60)
    print(f"Calculated dq (d mod q-1) [TOTAL LENGTH: {len(dq_bin)} bits]")
    print("-" * 60)
    print(dq_bin)
    print("=" * 60)

    with open("dp_full.txt", "w") as f:
        f.write(dp_bin)
    with open("dq_full.txt", "w") as f:
        f.write(dq_bin)

if __name__ == "__main__":
    main()
```
이 파이썬 스크립트를 활용하면 CRT-RSA에 의해 나눠진 키를 볼 수 있습니다.

### 4. 암호화
```
user@Ubuntu:~/css/flush-reload-attacks/flush-reload$ echo "secret message zzz" > data.txt
user@Ubuntu:~/css/flush-reload-attacks/flush-reload$ $GPG -r flush@reload.kr -e data.txt 
user@Ubuntu:~/css/flush-reload-attacks/flush-reload$ ls
cachebench  data.txt.gpg  gnupg-1.4.13  key-dump.txt  original-from-authors  secret-key.asc
data.txt    d_hex.txt     gpg-test      myversion     rdtsc-consistency      setup-attack.sh
```
data.txt.gpg가 성공적으로 생성된 모습을 확인할 수 있습니다. 복호화는 다음과 같습니다.
```
$GPG --decrypt data.txt.gpg
```

실제로 디버깅을 해보면 $d_p$와 똑같이 시퀀스가 진행되는 것을 볼 수 있습니다.

### 5. spy 프로그램 작성
