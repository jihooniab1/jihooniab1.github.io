---
title: "시스템 해킹 심화"
date: 2025-01-13 00:00:00 +0900
categories: [CTF]
tags: [pwnable]
permalink: /posts/dr-pwnable-advanced/
---
## seccomp

샌드박스 메커니즘의 일부입니다. <br>
**seccomp-tools** -> SECCOMP 바이너리 분석을 도와줍니다.

### Sandbox

**Allow List**와 **Deny List** 중에서 선택할 수 있습니다. 필요한 시스템 콜, 파일 접근 등만 허용합니다. <br>

### SECCOMP

SECCOMP: SECure COMPuting mode, 리눅스 커널을 위한 샌드박스 메커니즘입니다. 불필요한 시스템 콜을 차단합니다. 두 가지 모드 중에서 선택할 수 있습니다.

```c
int __secure_computing(const struct seccomp_data *sd) {
  int mode = current->seccomp.mode;
  int this_syscall;
  ...
  this_syscall = sd ? sd->nr : syscall_get_nr(current, task_pt_regs(current));
  switch (mode) {
    case SECCOMP_MODE_STRICT:
      __secure_computing_strict(this_syscall); /* may call do_exit */
      return 0;
    case SECCOMP_MODE_FILTER:
      return __seccomp_filter(this_syscall, sd, false);
    ...
  }
}
```

#### Strict Mode
**read**, **write**, **exit**, **sigreturn** 시스템 콜만 허용하고 나머지는 모두 종료합니다.

#### Filter Mode
시스템 콜을 선택적으로 허용하거나 거부할 수 있습니다 -> 1. 라이브러리 함수 사용 2. BPF(Berkelely Packet Filter) 사용

```
apt install libseccomp-dev libseccomp2 seccomp
```
seccomp 설치

### STRICT_MODE
```c
static const int mode1_syscalls[] = {
    __NR_seccomp_read,
    __NR_seccomp_write,
    __NR_seccomp_exit,
    __NR_seccomp_sigreturn,
    -1, /* negative terminated */
};
#ifdef CONFIG_COMPAT
static int mode1_syscalls_32[] = {
    __NR_seccomp_read_32,
    __NR_seccomp_write_32,
    __NR_seccomp_exit_32,
    __NR_seccomp_sigreturn_32,
    0, /* null terminated */
};
#endif
static void __secure_computing_strict(int this_syscall) {
  const int *allowed_syscalls = mode1_syscalls;
#ifdef CONFIG_COMPAT
  if (in_compat_syscall()) allowed_syscalls = get_compat_mode1_syscalls();
#endif
  do {
    if (*allowed_syscalls == this_syscall) return;
  } while (*++allowed_syscalls != -1);
#ifdef SECCOMP_DEBUG
  dump_stack();
#endif
  seccomp_log(this_syscall, SIGKILL, SECCOMP_RET_KILL_THREAD, true);
  do_exit(SIGKILL);
}
```

애플리케이션이 시스템 콜을 호출하면 **__secure_computing** 함수에 진입합니다. syscall 번호가 **mode1_syscalls** 또는 **mode1_syscalls_32**에 포함되어 있는지 비교합니다.

### FILTER_MODE: Library
시스템 콜을 선택적으로 허용하거나 거부합니다. SECCOMP는 아래 함수들을 지원합니다.

| 함수                    | 설명                                                            |
|-------------------------|-----------------------------------------------------------------|
| `seccomp_init`           | SECCOMP 모드의 초기값을 설정합니다. 임의의 syscall이 호출되면 해당 이벤트가 트리거됩니다 |
| `seccomp_rule_add`       | SECCOMP 모드에 대한 규칙을 추가합니다. 시스템 콜을 허용하거나 거부합니다 |
| `seccomp_load`           | 애플리케이션에 규칙을 적용합니다                        |

#### ALLOW LIST
아래 코드는 seccomp 라이브러리 함수를 사용하여 선택된 syscall을 허용합니다. 먼저 **SCMP_ACT_KILL**로 모든 syscall을 거부하는 규칙을 만들고, 그런 다음 허용 규칙을 추가하고 적용합니다.
```c
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
void sandbox() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  if (ctx == NULL) {
    printf("seccomp error\n");
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
  seccomp_load(ctx);
}
int banned() { fork(); }
int main(int argc, char *argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));
  sandbox();
  if (argc < 2) {
    banned();
  }
  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
}
```

#### DENY LIST
아래 코드는 seccomp 라이브러리 함수를 사용하여 선택된 syscall을 거부합니다. 먼저 모든 syscall을 허용하는 규칙을 만들고, 그런 다음 거부 규칙을 추가하고 적용합니다.
```c
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
void sandbox() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(openat), 0);
  seccomp_load(ctx);
}
int main(int argc, char *argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));
  sandbox();
  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
}
```
### FILTER_MODE: BPF
BPF: 커널이 지원하는 가상 머신으로, 원래 네트워크 패킷 필터링 및 분석에 사용되었습니다. 데이터 비교, 특정 명령으로 분기하는 기능을 제공합니다. <br>
syscall 이벤트를 처리하는 방법을 정의할 수 있습니다.
| Command        | Description                                               |
|----------------|-----------------------------------------------------------|
| `BPF_LD`       | 인자로 전달된 값을 누산기에 복사합니다. 이를 통해 후속 비교 문에서 값을 비교할 수 있습니다. |
| `BPF_JMP`      | 지정된 위치로 분기합니다.                            |
| `BPF_JEQ`      | 비교 조건이 만족되면 지정된 위치로 분기합니다. |
| `BPF_RET`      | 인자로 전달된 값을 반환합니다.                      |

#### BPF Macro
편리한 사용을 위해 매크로를 제공합니다.
##### BPF_STMT
지정된 **opcode**를 사용하여 **operand**에 해당하는 값을 가져옵니다. **opcode**는 전달된 인자의 어느 인덱스에서 어느 바이트를 가져올지 지정합니다.
```
BPF_STMT(opcode, operand)
```
##### BPF_JUMP
BPF_STMT 매크로를 사용하여 저장된 값을 **opcode**에 정의된 **operand**와 비교하고, 비교 결과에 따라 특정 오프셋으로 분기합니다.
```
BPF_JUMP(opcode, operand, true_offset, false_offset)
```

#### ALLOW LIST
**sandbox** 함수에서 **filter** 구조체 내부에 BPF 코드를 찾을 수 있습니다.
```c
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#define ALLOW_SYSCALL(name)                               \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define KILL_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))
/* architecture x86_64 */
#define ARCH_NR AUDIT_ARCH_X86_64
int sandbox() {
  struct sock_filter filter[] = {
      /* Validate architecture. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
      /* Get system call number. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),
      /* List allowed syscalls. */
      ALLOW_SYSCALL(rt_sigreturn),
      ALLOW_SYSCALL(open),
      ALLOW_SYSCALL(openat),
      ALLOW_SYSCALL(read),
      ALLOW_SYSCALL(write),
      ALLOW_SYSCALL(exit_group),
      KILL_PROCESS,
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
    return -1;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    perror("Seccomp filter error\n");
    return -1;
  }
  return 0;
}
void banned() { fork(); }
int main(int argc, char* argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));
  sandbox();
  if (argc < 2) {
    banned();
  }
  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
  return 0;
}
```

##### 아키텍처 검사
현재 아키텍처가 **X86_64**이면 다음 코드로 분기하고, 그렇지 않으면 종료하고 프로세스를 종료합니다.
```c
#define arch_nr (offsetof(struct seccomp_data, arch))
#define ARCH_NR AUDIT_ARCH_X86_64
BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
```

##### 시스템 콜 검사
syscall 번호를 저장하고 **ALLOW_SYSCALL** 매크로를 호출합니다. <br>
이 매크로는 호출된 시스템 콜과 인자로 전달된 시스템 콜을 비교하고, 일치하면 **SECCOMP_RET_ALLOW**를 반환합니다. 시스템 콜이 다르면 종료합니다.
```c
#define ALLOW_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define KILL_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
ALLOW_SYSCALL(rt_sigreturn),
ALLOW_SYSCALL(open),
ALLOW_SYSCALL(openat),
ALLOW_SYSCALL(read),
ALLOW_SYSCALL(write),
ALLOW_SYSCALL(exit_group),
KILL_PROCESS,
```

#### DENY LIST
```c
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#define DENY_SYSCALL(name)                                \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
#define MAINTAIN_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))
/* architecture x86_64 */
#define ARCH_NR AUDIT_ARCH_X86_64
int sandbox() {
  struct sock_filter filter[] = {
      /* Validate architecture. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
      /* Get system call number. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),
      /* List allowed syscalls. */
      DENY_SYSCALL(open),
      DENY_SYSCALL(openat),
      MAINTAIN_PROCESS,
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
    return -1;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    perror("Seccomp filter error\n");
    return -1;
  }
  return 0;
}
int main(int argc, char* argv[]) {
  char buf[256];
  int fd;
  memset(buf, 0, sizeof(buf));
  sandbox();
  fd = open("/bin/sh", O_RDONLY);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
  return 0;
}
```

##### 아키텍처 검사
현재 아키텍처가 **X86_64**이면 다음 코드로 분기하고, 그렇지 않으면 종료하고 프로세스를 종료합니다.
```c
#define arch_nr (offsetof(struct seccomp_data, arch))
#define ARCH_NR AUDIT_ARCH_X86_64
BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
```

##### 시스템 콜 검사
syscall 번호를 저장하고 **DENY_SYSCALL** 매크로를 호출합니다. <br>
이 매크로는 호출된 시스템 콜과 인자로 전달된 시스템 콜을 비교하고, 일치하면 종료합니다.
```c
#define DENY_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
#define MAINTAIN_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
DENY_SYSCALL(open),
DENY_SYSCALL(openat),
MAINTAIN_PROCESS,
```

## Master Canary
스택 카나리에 대한 더 고급 내용입니다.

### TLS: Thread Local Storage
#### Thread Local Storage
TLS: 스레드의 저장소입니다. TLS는 스레드의 전역 변수를 저장하기 위한 공간이며, **loader**에 의해 할당됩니다. <br>
**_dl_allocate_tls_storage** 함수가 TLS 영역을 할당하고, tcbp에 저장하고, **TLS_INIT_TP** 매크로에 전달합니다.
```c
static void *
init_tls (void)
{
  /* Construct the static TLS block and the dtv for the initial
     thread.  For some platforms this will include allocating memory
     for the thread descriptor.  The memory for the TLS block will
     never be freed.  It should be allocated accordingly.  The dtv
     array can be changed if dynamic loading requires it.  */
  void *tcbp = _dl_allocate_tls_storage ();
  if (tcbp == NULL)
    _dl_fatal_printf ("\
cannot allocate TLS data structures for initial thread\n");

  /* Store for detection of the special case by __tls_get_addr
     so it knows not to pass this dtv to the normal realloc.  */
  GL(dl_initial_dtv) = GET_DTV (tcbp);

  /* And finally install it for the main thread.  */
  const char *lossage = TLS_INIT_TP (tcbp);
  if (__glibc_unlikely (lossage != NULL))
    _dl_fatal_printf ("cannot set up thread-local storage: %s\n", lossage);
  tls_init_tp_called = true;

  return tcbp;
}
```
#### SET_FS
아래 코드는 할당된 TLS 영역을 **FS**로 초기화하는 **TLS_INIT_TP** 매크로 코드입니다. **arch_prctl**의 첫 번째 매개변수는 **ARCH_SET_FS**이고, 두 번째 매개변수는 TLS 주소입니다. <br>
**arch_prctl**의 **ARCH_SET_FS**는 프로세스의 **FS** 세그먼트 레지스터를 초기화합니다(TLS 영역을 가리키도록 만듭니다).
```c
# define TLS_INIT_TP(thrdescr) \
  ({ void *_thrdescr = (thrdescr);                                              \
     tcbhead_t *_head = _thrdescr;                                              \
     int _result;                                                              \
                                                                              \
     _head->tcb = _thrdescr;                                                      \
     /* For now the thread descriptor is at the same address.  */              \
     _head->self = _thrdescr;                                                      \
                                                                              \
     /* It is a simple syscall to set the %fs value for the thread.  */              \
     asm volatile ("syscall"                                                      \
                   : "=a" (_result)                                              \
                   : "0" ((unsigned long int) __NR_arch_prctl),                      \
                     "D" ((unsigned long int) ARCH_SET_FS),                      \
                     "S" (_thrdescr)                                              \
                   : "memory", "cc", "r11", "cx");                              \
                                                                              \
    _result ? "cannot set %fs base address for thread-local storage" : 0;     \
  })

```

### Master Canary
카나리: **FS:0x28**에서 가져와 RBP 바로 앞에 삽입합니다. <br>
FS -> TLS를 가리킴, TLS 주소에서 0x28바이트만큼 떨어진 주소에 위치한 랜덤 값이 **Master Canary**입니다. <br>
아래 코드는 **security_init** 함수로, 할당된 TLS 영역에 랜덤 카나리 값을 삽입합니다.
```c
static void
security_init (void)
{
  /* Set up the stack checker's canary.  */
  uintptr_t stack_chk_guard = _dl_setup_stack_chk_guard (_dl_random);
#ifdef THREAD_SET_STACK_GUARD
  THREAD_SET_STACK_GUARD (stack_chk_guard);
#else
  __stack_chk_guard = stack_chk_guard;
#endif

  /* Set up the pointer guard as well, if necessary.  */
  uintptr_t pointer_chk_guard
    = _dl_setup_pointer_guard (_dl_random, stack_chk_guard);
#ifdef THREAD_SET_POINTER_GUARD
  THREAD_SET_POINTER_GUARD (pointer_chk_guard);
#endif
  __pointer_chk_guard_local = pointer_chk_guard;

  /* We do not need the _dl_random value anymore.  The less
     information we leave behind, the better, so clear the
     variable.  */
  _dl_random = NULL;
}
```
**_dl_setup_stack_chk_guard** 함수가 카나리를 생성합니다.

#### 카나리 생성
**_dl_setup_stack_chk_guard** 함수는 **security_init**에 의해 처음 호출됩니다. **dl_random** 포인터에서 union 변수 **ret**로 데이터를 복사합니다. 그런 다음 바이너리의 바이트 순서에 따라 AND 연산을 수행합니다(리틀 엔디안이면 첫 번째 바이트를 NULL로).
```c
static inline uintptr_t __attribute__ ((always_inline))
_dl_setup_stack_chk_guard (void *dl_random)
{
  union
  {
    uintptr_t num;
    unsigned char bytes[sizeof (uintptr_t)];
  } ret = { 0 };

  if (dl_random == NULL)
    {
      ret.bytes[sizeof (ret) - 1] = 255;
      ret.bytes[sizeof (ret) - 2] = '\n';
    }
  else
    {
      memcpy (ret.bytes, dl_random, sizeof (ret));
#if BYTE_ORDER == LITTLE_ENDIAN
      ret.num &= ~(uintptr_t) 0xff;
#elif BYTE_ORDER == BIG_ENDIAN
      ret.num &= ~((uintptr_t) 0xff << (8 * (sizeof (ret) - 1)));
```
#### 카나리 삽입
생성된 카나리는 **THREAD_SET_STACK_GUARD** 매크로의 매개변수로 전달됩니다. **THREAD_SETMEM** 매크로를 사용하여 header.stack_guard 주소에 값을 삽입합니다.
```c
/* Set the stack guard field in TCB head.  */
#define THREAD_SET_STACK_GUARD(value) \
  THREAD_SETMEM (THREAD_SELF, header.stack_guard, value)
```

할당된 TLS 영역 => **tcbhead_t** 구조체입니다. **stack_guard**: 스택 카나리의 값을 보유하는 멤버 변수입니다.
```c
typedef struct
{
  void *tcb;		/* Pointer to the TCB.  Not necessarily the
			   thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;		/* Pointer to the thread descriptor.  */
  int multiple_threads;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  uintptr_t pointer_guard;
  int gscope_flag;
#ifndef __ASSUME_PRIVATE_FUTEX
  int private_futex;
#else
  int __glibc_reserved1;
#endif
  /* Reservation of some values for the TM ABI.  */
  void *__private_tm[4];
  /* GCC split stack support.  */
  void *__private_ss;
} tcbhead_t;
```

## Linux Library exploit
프로세스가 종료되는 방법을 분석해봅시다. (Ubuntu 18.04, Glibc 2.27 기반)

### _rtld_global
#### __GI_exit
프로그램을 종료할 때 많은 내부 코드가 실행됩니다. <br>
main 종료 -> **__GI_exit** -> **__run_exit_handlers**
```
=> 0x7ffff7a25240 <__GI_exit>:	lea    rsi,[rip+0x3a84d1]        # 0x7ffff7dcd718 <__exit_funcs>
   0x7ffff7a25247 <__GI_exit+7>:	sub    rsp,0x8
   0x7ffff7a2524b <__GI_exit+11>:	mov    ecx,0x1
   0x7ffff7a25250 <__GI_exit+16>:	mov    edx,0x1
   0x7ffff7a25255 <__GI_exit+21>:	call   0x7ffff7a24ff0 <__run_exit_handlers>
```
#### __run_exit_handlers
```c
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
{
	  const struct exit_function *const f = &cur->fns[--cur->idx];
	  switch (f->flavor)
	    {
	      void (*atfct) (void);
	      void (*onfct) (int status, void *arg);
	      void (*cxafct) (void *arg, int status);
	    case ef_free:
	    case ef_us:
	      break;
	    case ef_on:
	      onfct = f->func.on.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (onfct);
#endif
	      onfct (status, f->func.on.arg);
	      break;
	    case ef_at:
	      atfct = f->func.at;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (atfct);
#endif
	      atfct ();
	      break;
	    case ef_cxa:
	      cxafct = f->func.cxa.fn;
#ifdef PTR_DEMANGLE
	      PTR_DEMANGLE (cxafct);
#endif
	      cxafct (f->func.cxa.arg, status);
	      break;
	    }
	}

```
**exit_function** 구조체의 멤버 변수에 따라 함수 포인터를 호출합니다. 아래는 구조체 코드입니다. 프로그램이 종료될 때 **_dl_fini**가 호출됩니다.
```c
struct exit_function
{
/* `flavour' should be of type of the `enum' above but since we need
   this element in an atomic operation we have to use `long int'.  */
long int flavor;
union
  {
void (*at) (void);
struct
  {
    void (*fn) (int status, void *arg);
    void *arg;
  } on;
struct
{
    void (*fn) (void *arg, int status);
    void *arg;
    void *dso_handle;
  } cxa;
  } func;
};
```

#### _dl_fini
아래는 로더에 위치한 **_dl_fini** 코드의 일부입니다. **_dl_load_lock**을 사용하여 매개변수로 **__rtld_lock_lock_recursive**를 호출합니다. -> **dl_rtld_lock_recursive**라는 함수 포인터입니다.
```c
# define __rtld_lock_lock_recursive(NAME) \
  GL(dl_rtld_lock_recursive) (&(NAME).mutex)

void
_dl_fini (void)
{
#ifdef SHARED
  int do_audit = 0;
 again:
#endif
  for (Lmid_t ns = GL(dl_nns) - 1; ns >= 0; --ns)
    {
      /* Protect against concurrent loads and unloads.  */
      __rtld_lock_lock_recursive (GL(dl_load_lock));
```

#### _rtld_global
**_dl_rtld_lock_recursive** 함수 포인터는 **rtld_lock_default_lock_recursive**의 주소를 가지고 있습니다. 함수 포인터가 위치한 영역은 읽기, 쓰기 권한을 가지고 있습니다 -> 덮어쓸 수 있습니다.
```c
gdb-peda$ p _rtld_global
_dl_load_lock = {
    mutex = {
      __data = {
        __lock = 0x0,
        __count = 0x0,
        __owner = 0x0,
        __nusers = 0x0,
        __kind = 0x1,
        __spins = 0x0,
        __elision = 0x0,
        __list = {
          __prev = 0x0,
          __next = 0x0
        }
      },
      __size = '\000' <repeats 16 times>, "\001", '\000' <repeats 22 times>,
      __align = 0x0
    }
  },
  _dl_rtld_lock_recursive = 0x7ffff7dd60e0 <rtld_lock_default_lock_recursive>,
  ...
}
gdb-peda$ p &_rtld_global._dl_rtld_lock_recursive
$2 = (void (**)(void *)) 0x7ffff7ffdf60 <_rtld_global+3840>
gdb-peda$ vmmap 0x7ffff7ffdf60
Start              End                Perm	Name
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/lib/x86_64-linux-gnu/ld-2.27.so

```
#### _rtld_global 초기화
아래 코드는 **dl_main**의 일부이며, **dl_rtld_lock_recursive** 함수 포인터가 초기화되는 것을 찾을 수 있습니다.
```c
static void
dl_main (const ElfW(Phdr) *phdr,
	 ElfW(Word) phnum,
	 ElfW(Addr) *user_entry,
	 ElfW(auxv_t) *auxv)
{
  GL(dl_init_static_tls) = &_dl_nothread_init_static_tls;
#if defined SHARED && defined _LIBC_REENTRANT \
    && defined __rtld_lock_default_lock_recursive
  GL(dl_rtld_lock_recursive) = rtld_lock_default_lock_recursive;
  GL(dl_rtld_unlock_recursive) = rtld_lock_default_unlock_recursive;
```

## SigReturn-Oriented Programming
### Signal
OS -> **User Mode**와 **Kernel Mode**로 나뉩니다. <br>
Signal -> 프로세스에 정보를 전달하는 매체입니다(예: SIGSEGV). 시그널이 발생하면 해당 코드가 **kernel mode**에서 실행되고 **user mode**로 돌아갑니다.
```c
#include<stdio.h>
#include<unistd.h>
#include<signal.h>
#include<stdlib.h>

void sig_handler(int signum){
  printf("sig_handler called.\n");
  exit(0);
}
int main(){
  signal(SIGALRM,sig_handler);
  alarm(5);
  getchar();
  return 0;
}
```
**SIGALRM** 시그널이 발생하면 -> **sig_handler** 함수를 실행합니다. 마치 user mode에서 모든 것을 하는 것처럼 보이지만, 시그널이 발생하면 kernel mode로 진입합니다. <br>
kernel mode에서 시그널을 처리한 후 user mode로 돌아가 프로세스 코드를 진행합니다. => user mode 상태를 기억해야 합니다(메모리, 레지스터..)

#### do_signal
do_signal: 시그널을 처리하기 위해 처음 호출됩니다. 최근 커널에서는 **arch_do_signal_or_restart**입니다. 시그널이 발생하면 시그널 정보를 매개변수로 사용하여 **get_signal**을 호출합니다. <br>
get_signal: 일치하는 핸들러가 등록되어 있는지 확인합니다. 등록되어 있으면 시그널 정보와 reg 정보를 매개변수로 사용하여 **handle_signal**을 호출합니다.

```c
void arch_do_signal_or_restart(struct pt_regs *regs, bool has_signal)
{
	struct ksignal ksig;
	if (has_signal && get_signal(&ksig)) {
		/* Whee! Actually deliver the signal.  */
		handle_signal(&ksig, regs);
		return;
	}
	/* Did we come from a system call? */
	if (syscall_get_nr(current, regs) >= 0) {
		/* Restart the system call - no handlers present */
		switch (syscall_get_error(current, regs)) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			regs->ax = regs->orig_ax;
			regs->ip -= 2;
			break;
		case -ERESTART_RESTARTBLOCK:
			regs->ax = get_nr_restart_syscall(regs);
			regs->ip -= 2;
			break;
		}
	}
	/*
	 * If there's no signal to deliver, we just put the saved sigmask
	 * back.
	 */
	restore_saved_sigmask();
}
```

#### handle_signal
아래 코드는 **handle_signal**의 일부로, **setup_rt_frame**을 호출합니다.
```c
static void
handle_signal(struct ksignal *ksig, struct pt_regs *regs)
{
    ...
	failed = (setup_rt_frame(ksig, regs) < 0);
	if (!failed) {
		fpu__clear_user_states(fpu);
	}
	signal_setup_done(failed, ksig, stepping);
}
```

**setup_rt_frame**을 살펴봅시다.

```c
int x64_setup_rt_frame(struct ksignal *ksig, struct pt_regs *regs)
{
	...

	/* Set up registers for signal handler */
	regs->di = ksig->sig;
	/* In case the signal handler was declared without prototypes */
	regs->ax = 0;

	/* This also works for non SA_SIGINFO handlers because they expect the
	   next argument after the signal number on the stack. */
	regs->si = (unsigned long)&frame->info;
	regs->dx = (unsigned long)&frame->uc;
	regs->ip = (unsigned long) ksig->ka.sa.sa_handler;

	regs->sp = (unsigned long)frame;

	/*
	 * Set up the CS and SS registers to run signal handlers in
	 * 64-bit mode, even if the handler happens to be interrupting
	 * 32-bit or 16-bit code.
	 *
	 * SS is subtle.  In 64-bit mode, we don't need any particular
	 * SS descriptor, but we do need SS to be valid.  It's possible
	 * that the old SS is entirely bogus -- this can happen if the
	 * signal we're trying to deliver is #GP or #SS caused by a bad
	 * SS value.  We also have a compatibility issue here: DOSEMU
	 * relies on the contents of the SS register indicating the
	 * SS value at the time of the signal, even though that code in
	 * DOSEMU predates sigreturn's ability to restore SS.  (DOSEMU
	 * avoids relying on sigreturn to restore SS; instead it uses
	 * a trampoline.)  So we do our best: if the old SS was valid,
	 * we keep it.  Otherwise we replace it.
	 */
	regs->cs = __USER_CS;
}
```

regs->ip => 다음 명령어에 핸들러의 주소를 삽입합니다.

### sigreturn
**context switching**이 발생하면 커널은 **save**와 **restore**를 수행해야 합니다. -> syscall **sigreturn**이 사용됩니다. <br>
아래 코드는 **restore_sigcontext**로, sigreturn syscall이 호출되면 내부적으로 restore_sigcontext를 호출하여 user mode로 돌아갑니다.
```c
static bool restore_sigcontext(struct pt_regs *regs,
			       struct sigcontext __user *usc,
			       unsigned long uc_flags)
{
	struct sigcontext sc;

	/* Always make any pending restarted system calls return -EINTR */
	current->restart_block.fn = do_no_restart_syscall;

	if (copy_from_user(&sc, usc, CONTEXT_COPY_SIZE))
		return false;

#ifdef CONFIG_X86_32
	set_user_gs(regs, sc.gs);
	regs->fs = sc.fs;
	regs->es = sc.es;
	regs->ds = sc.ds;
#endif /* CONFIG_X86_32 */

	regs->bx = sc.bx;
	regs->cx = sc.cx;
	regs->dx = sc.dx;
	regs->si = sc.si;
	regs->di = sc.di;
	regs->bp = sc.bp;
	regs->ax = sc.ax;
	regs->sp = sc.sp;
	regs->ip = sc.ip;

#ifdef CONFIG_X86_64
	regs->r8 = sc.r8;
	regs->r9 = sc.r9;
	regs->r10 = sc.r10;
	regs->r11 = sc.r11;
	regs->r12 = sc.r12;
	regs->r13 = sc.r13;
	regs->r14 = sc.r14;
	regs->r15 = sc.r15;
#endif /* CONFIG_X86_64 */

	/* Get CS/SS and force CPL3 */
	regs->cs = sc.cs | 0x03;
	regs->ss = sc.ss | 0x03;

	regs->flags = (regs->flags & ~FIX_EFLAGS) | (sc.flags & FIX_EFLAGS);
	/* disable syscall checks */
	regs->orig_ax = -1;

#ifdef CONFIG_X86_64
	/*
	 * Fix up SS if needed for the benefit of old DOSEMU and
	 * CRIU.
	 */
	if (unlikely(!(uc_flags & UC_STRICT_RESTORE_SS) && user_64bit_mode(regs)))
		force_valid_ss(regs);
#endif

	return fpu__restore_sig((void __user *)sc.fpstate,
			       IS_ENABLED(CONFIG_X86_32));
}
```

### SROP
SROP: SigReturn-Oriented Programming (SROP)은 **sigreturn** syscall을 사용하는 ROP입니다. -> 모든 레지스터를 조작할 수 있습니다. <br>
스택에 레지스터로 복사할 값을 준비하고, 그런 다음 sigreturn을 호출합니다.

```c
#include <string.h>

int main()
{
        char buf[1024];
        memset(buf, 0x41, sizeof(buf));

        asm("mov $15, %rax;"
            "syscall");
}

RBX: 0x4141414141414141 ('AAAAAAAA')
RCX: 0x4141414141414141 ('AAAAAAAA')
RDX: 0x4141414141414141 ('AAAAAAAA')
RSI: 0x4141414141414141 ('AAAAAAAA')
RDI: 0x4141414141414141 ('AAAAAAAA')
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x4141414141414141 ('AAAAAAAA')
RIP: 0x4141414141414141 ('AAAAAAAA')
R8 : 0x4141414141414141 ('AAAAAAAA')
R9 : 0x4141414141414141 ('AAAAAAAA')
R10: 0x4141414141414141 ('AAAAAAAA')
R11: 0x4141414141414141 ('AAAAAAAA')
R12: 0x4141414141414141 ('AAAAAAAA')
R13: 0x4141414141414141 ('AAAAAAAA')
R14: 0x4141414141414141 ('AAAAAAAA')
R15: 0x4141414141414141 ('AAAAAAAA')
```
