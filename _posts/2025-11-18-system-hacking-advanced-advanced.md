---
title: "System hacking Advanced"
date: 2025-11-18 01:41:18 +0900
categories: [CTF, Dreamhack, Pwnable]
tags: []
---

# System hacking Advanced

Studying system hacking advanced things. 
 
## Index
- [1. seccomp](#seccomp)
- [2. Master Canary](#master-canary)
- [3. Linux Library exploit](#linux-library-exploit)

## seccomp

Part of Sanbox mechanism <br>
**seccomp-tools** -> Help analyzing SECCOMP binary 

### Sandbox

Can choose between **Allow List** and **Deny List**, Only allow necessary system call, file access, etc. <br>

### SECCOMP

SECCOMP: SECure COMPuting mode, Sandbox mechanism for Linux Kernel. Block unnecessary system call. Can choose between two mode. 

```
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
Only allow **read**, **write**, **exit**, **sigreturn** system call and kill everything else

#### Filter Mode
Can allow or deny system calls selectively -> 1. Use library functions 2. Use BPF(Berkelely Packet Filter) 

```
apt install libseccomp-dev libseccomp2 seccomp
```
Install seccomp

### STRICT_MODE
```
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

When application calls system call, enter **__secure_computing** function. Compare if syscall number is included in **mode1_syscalls** or **mode1_syscalls_32**. 

### FILTER_MODE: Library
Allow or deny system call selectively. SECCOMP supports functions below 

| 함수                    | 설명                                                            |
|-------------------------|-----------------------------------------------------------------|
| `seccomp_init`           | Set initial value of SECCOMP mode. When arbitrary syscall called, corresponding event trigger |
| `seccomp_rule_add`       | Add rule for SECCOMP mode. Allow or deny system call |
| `seccomp_load`           | Apply rules to application                        |

#### ALLOW LIST
Below code allows selected syscall using seccomp library functions. First, make rule that deny every syscall with **SCMP_ACT_KILL**, and then add allow rule, apply. 
```
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
Below code denies selected syscall using seccomp library functions. First, make rule that allow every syscall, and then add deny rule, apply.
```
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
BPF: Virtual Machine that kernel supports, originaly used for network packet filtering and analyzing. Provides functions for data compare, branching into specific command <br>
Can define how to deal with syscall events. 
| Command        | Description                                               |
|----------------|-----------------------------------------------------------|
| `BPF_LD`       | Copies the value passed as an argument into the accumulator. This allows the value to be compared in subsequent comparison statements. |
| `BPF_JMP`      | Branches to a specified location.                            |
| `BPF_JEQ`      | Branches to a specified location if the comparison condition is met. |
| `BPF_RET`      | Returns the value passed as an argument.                      |

#### BPF Macro 
Provides macro for convenient use.
##### BPF_STMT
It retrieves the value corresponding to the **operand** using the specified **opcode**. The **opcode** specifies which byte from which index of the passed argument should be fetched.
```
BPF_STMT(opcode, operand)
```
##### BPF_JUMP
Compares the value stored using the BPF_STMT macro with the **operand** defined in the **opcode**, and branches to a specific offset based on the comparison result.
```
BPF_JUMP(opcode, operand, true_offset, false_offset)
```

#### ALLOW LIST
In **sandbox** function, can find BPF code inside **filter** struct. 
```
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

##### Inspect Architecture
If current arch is **X86_64** branch to next code, if not kill and terminate. 
```
#define arch_nr (offsetof(struct seccomp_data, arch))
#define ARCH_NR AUDIT_ARCH_X86_64
BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
```

##### Inspect system call
Store syscall number, call **ALLOW_SYSCALL** macro. <br>
The macro compares the called system call with the system call passed as an argument, and if they match, it returns **SECCOMP_RET_ALLOW**. If the system calls are different, terminate.
```
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
```
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

##### Inspect Architecture
If current arch is **X86_64** branch to next code, if not kill and terminate. 
```
#define arch_nr (offsetof(struct seccomp_data, arch))
#define ARCH_NR AUDIT_ARCH_X86_64
BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
```

##### Inspect system call
Store syscall number, call **DENY_SYSCALL** macro. <br>
The macro compares the called system call with the system call passed as an argument, and if they match, terminate. 
```
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
More advanced thing about stact canary. 

### TLS: Thread Local Storage
#### Thread Local Storage
TLS: Storage of thread. TLS is space for storing global variable of thread, allocated by **loader**. <br>
**_dl_allocate_tls_storage** function allocate TLS area, store it at tcbp, and give it to **TLS_INIT_TP** Macro.
```
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
Below code is **TLS_INIT_TP** Macro code that initialize allocated TLS area into **FS**. First paramter of **arch_prctl** is **ARCH_SET_FS**, and second parameter is TLS address. <br>
**ARCH_SET_FS** of **arch_prctl** initialize **FS** segment register of process(make it point TLS area)
```
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
Canary: Fetch from **FS:0x28** and insert it right before RBP. <br>
FS -> pointing TLS, Random value located at an address by 0x28 bytes from TLS address is **Master Canary** <br>
Below code is **security_init** function, insert random canary value into allocated TLS area
```
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
**_dl_setup_stack_chk_guard** function creates canary. 

#### Canary Generation
**_dl_setup_stack_chk_guard** function is first called by **security_init**. It copies data from **dl_random** pointer into union variable **ret**. After that AND operation according to binary's byte ordering(if little, first byte NULL)
```
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
#### Canary Insertion
Generated canary transmitted into parameter of **THREAD_SET_STACK_GUARD** macro. With **THREAD_SETMEM** macro, insert value into header.stack_guard address.
```
/* Set the stack guard field in TCB head.  */
#define THREAD_SET_STACK_GUARD(value) \
  THREAD_SETMEM (THREAD_SELF, header.stack_guard, value)
```

Allocated TLS area => **tcbhead_t** struct. **stack_guard**: member variable that holds the value of stack canary. 
```
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
Let's analyze how processes are terminated. (Based on Ubuntu 18.04, Glibc 2.27)

### _rtld_global
#### __GI_exit
When terminating program, lot's of internal code is executed. <br>
main finish -> **__GI_exit** -> **__run_exit_handlers**
```
=> 0x7ffff7a25240 <__GI_exit>:	lea    rsi,[rip+0x3a84d1]        # 0x7ffff7dcd718 <__exit_funcs>
   0x7ffff7a25247 <__GI_exit+7>:	sub    rsp,0x8
   0x7ffff7a2524b <__GI_exit+11>:	mov    ecx,0x1
   0x7ffff7a25250 <__GI_exit+16>:	mov    edx,0x1
   0x7ffff7a25255 <__GI_exit+21>:	call   0x7ffff7a24ff0 <__run_exit_handlers>
```
#### __run_exit_handlers
```
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
Calling function pointer according to member variable of **exit_function** struct. Below is struct code. When program terminates, **_dl_fini** is called.
```
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
Below is part of **_dl_fini** code located at loader. It calls **__rtld_lock_lock_recursive** with parameter using **_dl_load_lock**. -> function pointer named **dl_rtld_lock_recursive** 
```
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
**_dl_rtld_lock_recursive** function pointer is holding address of **rtld_lock_default_lock_recursive**. Area where function pointer locates have read, write privilege -> Can overwrite 
```
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
#### _rtld_global initialization
Below code is part of **dl_main**, can find **dl_rtld_lock_recursive** function pointer is initialized.
```
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
OS -> Devided into **User Mode** and **Kernel Mode**. <br>
Signal -> Medium for information transmission to a process(ex: SIGSEGV). When signal occur, corresponding code executes in **kernel mode** and then return to **user mode**.
```
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
When **SIGALRM** signal occur -> executes **sig_handler** function. Looks like user mode doing everything, but when signal occur enters kernel mode. <br>
After dealing with signal in kernel mode, return to user mode and proceed process code. => Have to remember user mode state(memory, register..)

#### do_signal
do_signal: First called to deal with signal. **arch_do_signal_or_restart** in recent kernel. When signal occur, calls **get_signal** using information of signal as parameter. <br>
get_signal: Check if matching handler is registered. If registered, call **handle_signal** using signal information and reg information as parameter. 

```
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
Below code is part of **handle_signal**, calling **setup_rt_frame**.
```
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

Let's look at **setup_rt_frame**.

```
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

regs->ip => Inserting the address of handler into next instruction. 

### sigreturn
When **context switching** happens, kernel has to do **save** and **restore**. -> syscall **sigreturn** is used. <br>
Below code is **restore_sigcontext**, when sigreturn syscall is called, it internally calls restore_sigcontext to return to user mode. 
```
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
SROP: SigReturn-Oriented Programming (SROP) is ROP that use **sigreturn** syscall. -> Can manipulate every register. <br>
Prepare values to copy to register in stack, and then call sigreturn

```
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

