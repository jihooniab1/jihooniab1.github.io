---
title: "Side Channel Practice_TDXDown"
date: 2026-04-13 00:00:00 +0900
categories: [Study]
tags: [security, side channel]
permalink: /posts/Side+Channel+Practice_2/
math: true
---

# 사이드 채널 실습 - TDXDown: Single-Stepping TD

## TDXDown
[Github](https://jihooniab1.github.io/posts/TDXdown/) 링크에 정리되어 있는 single-stepping 논문 공격을 실제로 수행해보는 포스트입니다. 연구실에서 제공하는 서버 환경은 다음과 같습니다.

```
ubuntu@ubuntu:/boot$ lscpu
Architecture:             x86_64
  CPU op-mode(s):         32-bit, 64-bit
  Address sizes:          45 bits physical, 48 bits virtual
  Byte Order:             Little Endian
CPU(s):                   64
  On-line CPU(s) list:    0-63
Vendor ID:                GenuineIntel
  Model name:             Intel(R) Xeon(R) 6710E
    CPU family:           6
    Model:                175
    Thread(s) per core:   1
    Core(s) per socket:   64
    Socket(s):            1
    Stepping:             3
    CPU(s) scaling MHz:   33%
    CPU max MHz:          2400.0000
    CPU min MHz:          800.0000
    BogoMIPS:             4800.00
...
```

아티팩트 코드는 [Zenodo](https://zenodo.org/records/12683611)에서 구할 수 있습니다. 

## 아티팩트
```
user@Ubuntu:~/Downloads/tdxdown-paper-artifacts/tdxdown-paper-artifacts$ ls -l
total 16
drwxr-xr-x 2 user user 4096 Apr 28  2024 'bios screenshots'
-rw-rw-r-- 1 user user 2065 Apr 29  2024  README.md
drwxrwxr-x 5 user user 4096 Apr 27  2024  single-stepping
drwxrwxr-x 5 user user 4096 Apr 28  2024  stumble-stepping
```

본 포스팅에서는 **single-stepping** 공격 관련 코드들을 분석하고 6.8.0 canonical/intel 커널에 이식해보고자 합니다.

### 자료구조 및 헤더
#### include/uapi/linux/kvm.h
```c
typedef struct {
	uint64_t gpa;
} tdx_step_block_page_t;
#define TDX_STEP_BLOCK_PAGE _IOWR(KVMIO, 0xf0, tdx_step_block_page_t)

typedef struct {
	uint64_t gpa;
} tdx_step_unblock_page_t;
#define TDX_STEP_UNLBOCK_PAGE _IOWR(KVMIO, 0xf1, tdx_step_unblock_page_t)

typedef struct {
	uint64_t cpu_id;
}tdx_step_send_ipi_t;
//send nmi ipi to selected cpu
#define TDX_STEP_SEND_IPI _IOWR(KVMIO, 0xf2, tdx_step_send_ipi_t)
...
```
`구조체 + 구조체를 인자로 쓰는 KVM ioctl 선언` 형태로 공격에 사용하는 ioctl들이 선언되어 있습니다. 종류는 다음과 같습니다.

| 번호 | 매크로 | 매크로 종류 | 인자 struct | 방향 | 역할 |                                                                                                                                 
|------|--------|-------------|-------------|------|------|                                                                                                                                 
| 0xf0 | TDX_STEP_BLOCK_PAGE | _IOWR | tdx_step_block_page_t | in | 지정 GPA 페이지 SEPT block |                                                                                            
| 0xf1 | TDX_STEP_UNLBOCK_PAGE | _IOWR | tdx_step_unblock_page_t | in | 위 block 해제 |                                                                                       
| 0xf2 | TDX_STEP_SEND_IPI | _IOWR | tdx_step_send_ipi_t | in | 지정 CPU에 NMI IPI 발사 |
| 0xf3 | TDX_STEP_FR_VMCS | _IOWR | tdx_step_fr_vmcs_t | in/out | 공격 메인 - config 넘기고 상태 머신 시작 |                                                                                
| 0xf4 | TDX_STEP_TERMINATE_FR_VMCS | _IOWR | tdx_step_terminate_fr_vmcs_t | in/out | 공격 종료 + 측정 결과 회수 |                                                                          
| 0xf5 | TDX_STEP_SET_REMAINING_CACHE_ATTACKS | _IO | 없음 | - | F+R 잔여 카운터 리셋 |                                                                                                     
| 0xf6 | TDX_STEP_IS_FR_VMCS_DONE | _IOWR | tdx_step_is_fr_vmcs_done_t | out | 공격 완료 여부 polling |                                                                                     
| 0xf7 | TDX_STEP_MAP_GPA | _IOWR | tdx_step_map_gpa_t | in/out | GPA → HPA 매핑 조회 |         

#### include/linux/tdx_step.h
`tdx_step.h`는 **공격 상태를 담는 구조체와 부속물 모음** 을 담고 있는 파일입니다. 공격은 7개 상태로 구성되어 있고 아래와 같습니다. 
```c
typedef enum {
	AS_INACTIVE,
	//Waiting for attack configuration to be applied
	AS_SETUP_PENDING,
	//wait for pagefault on target gpa
	AS_WAITING_FOR_TARGET,
	//Single step until we get parge fault for done marker
	AS_WAITING_FOR_DONE_MARKER,
	//We got our target and are now waiting for the end of the sequence
	AS_WAITING_FOR_END_OF_SEQ,
	//We got an unexpected access during AS_WAITING_FOR_DONE_MARKER and are now waiting for a trigger to return to that state
	AS_WAITING_FOR_REENTER,
	//Waiting for single step configuration to be cleared
	AS_TEARDOWN_PENDING,
	AS_MAX,
} attack_state_t;
```

그리고 `tdx_step_config_t` 구조체는 config를 받아 공격 설정을 저장하고, 공격 전체의 상태(`attack_cfg.state`)를 관리하는 구조체로, 공격 한 사이클의 정보를 모두 담고 있습니다.
```c
typedef struct {
    uint32_t timer_value;
    uint64_t entries_since_stepping_attack;
    //number of entries during the active attack phase
	uint64_t entries_while_active_stepping_attack;
    apic_backup_t apic_backup;
    attack_cfg_t attack_cfg;

    //set this flag if we supressed an interrupt during our stepping attack
    bool suppressed_interrupt_during_stepping;
	int suppressed_interrupt_delivery_mode;
	int suppressed_interrupt_trig_mode;
	int suppressed_interrupt_vector;

    bool block_gpa_valid;
    uint64_t block_gpa;
    uint64_t gpa_blocked;
    
    struct page* pinned_page_shared_mem;
    uint64_t* mapping_shared_mem; 

    //might be 0, if feature not activated by user
    uint8_t* mapping_victim_code;



    //idt related vars

    /// @brief core on which idt was retrieved or -1 if idt has never been fetched
	int got_idt_on_cpu;
	/// @brief if got_idt_on_cpu != -1, this holds the idt for that core
	idt_t idt;
    gate_desc_t old_idt_gate;
    bool running_with_custom_apic_handler;

    /* if this array is not null,
     * access these tdvps pages directly before VM entry
     * and again after VM exit
    */
    uint64_t* targeted_tdvps_addrs;
    uint64_t targeted_tdvps_addrs_len;

    uint64_t* all_tdvps_addrs;
    uint64_t* timings_all_tdvps_addrs;
    uint64_t all_tdvps_addrs_count;
	//might be NULL if attack type not STUMBLE_STEP
    volatile uint64_t* attacked_tdvps_addr;


    //Track if we have already called my_split_all_pages for this VM
	bool called_split_pages;
    fr_monitor_thread_ctx_t *fr_ctx;

	//type of attack that should be performed
	attack_type_t attack_type;
} tdx_step_config_t;
```

### 저수준 SEMCALL / 어셈블리
#### arch/x86/virt/vmx/tdxcall.S, KVM 진입 과정
tdxcall.S는 SEAMCALL/TDCALL을 발사하는 어셈블리 헬퍼입니다. SEAMCALL은 KVM이 TDX 모듈에게 TD 관련 요청을 보낼 때 사용하고, TDCALL은 TD가 게스트 OS의 자원 요청을 TDX 모듈에게 보낼 때 사용합니다. 호스트 커널 스케줄러가 QEMU의 vCPU 스레드를 깨우는 상황을 살펴보겠습니다. QEMU 버전은 8.2.2 코드를 참고하였습니다.

QEMU는 vCPU를 스레드 형태로 관리합니다. 스레드가 스케줄링 되면 vCPU가 CPU를 빌려 실행을 하는 구조라고 생각할 수 있습니다.
```c
static void *kvm_vcpu_thread_fn(void *arg)
{
    CPUState *cpu = arg;
    int r;

    rcu_register_thread();

    qemu_mutex_lock_iothread();
    qemu_thread_get_self(cpu->thread);
    cpu->thread_id = qemu_get_thread_id();
    cpu->neg.can_do_io = true;
    current_cpu = cpu;

    r = kvm_init_vcpu(cpu, &error_fatal);
    kvm_init_cpu_signals(cpu);

    /* signal CPU creation */
    cpu_thread_signal_created(cpu);
    qemu_guest_random_seed_thread_part2(cpu->random_seed);

    do {
        if (cpu_can_run(cpu)) {
            r = kvm_cpu_exec(cpu);
            if (r == EXCP_DEBUG) {
                cpu_handle_guest_debug(cpu);
            }
        }
        qemu_wait_io_event(cpu);
    } while (!cpu->unplug || cpu_can_run(cpu));

    kvm_destroy_vcpu(cpu);
    cpu_thread_signal_destroyed(cpu);
    qemu_mutex_unlock_iothread();
    rcu_unregister_thread();
    return NULL;
}
```
`kvm_vcpu_thread_fn` 함수는 **QEMU가 vCPU 개수만큼 만든 pthread의 진입 함수** 입니다. 

초반부에는 RCU에 스레드를 등록하고 커널에 vCPU 자료구조를 만든 후 **vCPU 준비됨** 시그널을 생성합니다. 중반의 메인 루프에서는 VM이 실행되는 동안 `KVM_RUN`으로 게스트를 실행하고, 시그널과 exit_request를 처리합니다. 후반부는 KVM 자료구조를 해제하는 부분입니다. 

```c
int kvm_cpu_exec(CPUState *cpu)
{
    // 1. Pre-run, kvm_arch_pre_run과 exit_request 체크, 진입 전 마지막 동기화
    do {
        MemTxAttrs attrs;

        if (cpu->vcpu_dirty) {
            ret = kvm_arch_put_registers(cpu, KVM_PUT_RUNTIME_STATE);
            cpu->vcpu_dirty = false;
        }

        kvm_arch_pre_run(cpu, run);
        if (qatomic_read(&cpu->exit_request)) {
            DPRINTF("interrupt exit requested\n");
            /*
             * KVM requires us to reenter the kernel after IO exits to complete
             * instruction emulation. This self-signal will ensure that we
             * leave ASAP again.
             */
            kvm_cpu_kick_self();
        }

        /* Read cpu->exit_request before KVM_RUN reads run->immediate_exit.
         * Matching barrier in kvm_eat_signals.
         */
        smp_rmb();

    // 2. KVM_RUN. 이 syscal 안에서 게스트가 실제로 실행됨
        run_ret = kvm_vcpu_ioctl(cpu, KVM_RUN, 0);

        attrs = kvm_arch_post_run(cpu, run);

    // 3. exit_reason_switch. ret=0이면 do-while 계속 돌고(다시 KVM_RUN), 아니면 함수 종료
        switch (run->exit_reason) {
        case KVM_EXIT_IO:  // PIO emulate
            DPRINTF("handle_io\n");
            /* Called outside BQL */
            kvm_handle_io(run->io.port, attrs,
                          (uint8_t *)run + run->io.data_offset,
                          run->io.direction,
                          run->io.size,
                          run->io.count);
            ret = 0;
            break;
        case KVM_EXIT_MMIO: // MMIO emulate
            DPRINTF("handle_mmio\n");
            /* Called outside BQL */
            address_space_rw(&address_space_memory,
                             run->mmio.phys_addr, attrs,
                             run->mmio.data,
                             run->mmio.len,
                             run->mmio.is_write);
            ret = 0;
            break;
        case KVM_EXIT_SHUTDOWN: // 게스트 종료
            DPRINTF("shutdown\n");
            qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
            ret = EXCP_INTERRUPT;
            break;
        case KVM_EXIT_MEMORY_FAULT: // TDX private <-> shared 변환
            if (run->memory_fault.flags & ~KVM_MEMORY_EXIT_FLAG_PRIVATE) {
                error_report("KVM_EXIT_MEMORY_FAULT: Unknown flag 0x%" PRIx64,
                             (uint64_t)run->memory_fault.flags);
                ret = -1;
                break;
            }
            ret = kvm_convert_memory(run->memory_fault.gpa, run->memory_fault.size,
                                     run->memory_fault.flags & KVM_MEMORY_EXIT_FLAG_PRIVATE);
            break;
        default: // arch 별 처리
            DPRINTF("kvm_arch_handle_exit\n");
            ret = kvm_arch_handle_exit(cpu, run);
            break;
        }
    } while (ret == 0);
```
위 코드는 `kvm_cpu_exec` 코드를 중요한 부분만 추린 코드입니다. kvm_cpu_exec은 KVM_RUN을 반복 호출하면서 게스트 실행을 끌고가는 함수입니다. `kvm_vcpu_thread_fn` 안에서 호출되며, 하나의 vCPU에 대해 KVM_RUN ioctl을 반복 실행하다가 QEMU 상위 처리(시그널, shutdown, 디버그 등)가 필요할 때만 반환하는 함수입니다. 

```c
int kvm_vcpu_ioctl(CPUState *cpu, int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    trace_kvm_vcpu_ioctl(cpu->cpu_index, type, arg);
    accel_cpu_ioctl_begin(cpu);
    ret = ioctl(cpu->kvm_fd, type, arg);
    accel_cpu_ioctl_end(cpu);
    if (ret == -1) {
        ret = -errno;
    }
    return ret;
}
```
QEMU의 마지막 함수로 이 다음은 커널로 흐름이 넘어갑니다. `kvm_vcpu_ioctl(cpu, KVM_RUN, 0)` 이런 식으로 호출되면 인자를 추출하고 **ioctl(kvm_fd, KVM_RUN, 0)** 을 호출합니다.

```c
static long kvm_vcpu_ioctl(struct file *filp,
			   unsigned int ioctl, unsigned long arg)
{
    // 1, fd -> vCPU 객체
	struct kvm_vcpu *vcpu = filp->private_data;
    
    // 2. 보안/일관성 검증. 
    // vcpu->kvm->mm은 VM을 만든 프로세스의 mm_struct. current->mm은 지금 ioctl을 부른 프로세스의 mm_struct. 호출자와 다른 프로세스가 게스트 메모리를 못 보도록 막는 것입니다. 
    // VM이 정리단계(vm_dead)에 들어갔으면 더 이상 ioctl을 받지 않는다는 의미입니다
	if (vcpu->kvm->mm != current->mm || vcpu->kvm->vm_dead)
		return -EIO;
	if (unlikely(_IOC_TYPE(ioctl) != KVMIO))
		return -EINVAL;

    // 3. vCPU 단위 mutex (한 번에 한 ioctl만 처리)
	if (mutex_lock_killable(&vcpu->mutex))
		return -EINTR;
	switch (ioctl) {
	case KVM_RUN: {
		struct pid *oldpid;
		r = -EINVAL;
		if (arg)
			goto out; // arg는 0이여야 합니다

        // 4. pid 변경 체크 (vCPU를 직전에 실행한 호스트 스레드와 지금 호출자가 다르면 호스트-CPU 종속 자료구조를 재셋업)
		oldpid = rcu_access_pointer(vcpu->pid);
		if (unlikely(oldpid != task_pid(current))) {
			/* The thread running this VCPU changed. */
			struct pid *newpid;

			r = kvm_arch_vcpu_run_pid_change(vcpu);
			if (r)
				break;

			newpid = get_task_pid(current, PIDTYPE_PID);
			rcu_assign_pointer(vcpu->pid, newpid);
			if (oldpid)
				synchronize_rcu();
			put_pid(oldpid);
		}

        // 5. 진짜 실행하는 부분
		r = kvm_arch_vcpu_ioctl_run(vcpu);
		trace_kvm_userspace_exit(vcpu->run->exit_reason, r);
        break;
    // 나머지 케이스들
```
`kvm_vcpu_ioctl` 함수는 QEMU에서 ioctl(vcpu_fd, ...) 호출하면 이를 검증하고, dispatch하는 함수입니다. `KVM_RUN`의 경우 ioctl에 대한 검증을 한 후 **kvm_arch_vcpu_ioctl_run(vcpu)** 함수가 호출됩니다.

```c
int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu)
{
    // 1. 사전 준비 단계. MMU 초기화를 마무리 하고 vCPU를 현재 CPU에 로드합니다(vcpu_load). 시그널 마스크를 활성화 하고 SRCU read lock을 하는 등, vCPU가 실행될 수 있도록 준비를 합니다.
	r = kvm_mmu_post_init_vm(vcpu->kvm);
	if (r)
		return r;

	vcpu_load(vcpu);
	kvm_sigset_activate(vcpu);
	kvm_run->flags = 0;
	kvm_load_guest_fpu(vcpu);

	kvm_vcpu_srcu_read_lock(vcpu);

    // 2. 진짜 실행(vcpu_run)
	r = vcpu_run(vcpu);

    // 3. 사후 정리 
out:
	kvm_put_guest_fpu(vcpu); // 게스트 FPU 저장, 호스트 FPU 복원 (FPU: Floating Point Unit, CPU 안의 실수 계산 + SIMD 전용 레지스터 세트)
	if (kvm_run->kvm_valid_regs)
		store_regs(vcpu); // 게스트 레지스터를 kvm_run->s.regs에 복사
	post_kvm_run_save(vcpu); // exit 정보 정리, ready_for_interrupt
	kvm_vcpu_srcu_read_unlock(vcpu);

	kvm_sigset_deactivate(vcpu);
	vcpu_put(vcpu);  // vCPU 비활성화
	return r; 
}
```
`kvm_arch_vcpu_ioctl_run`함수는 kvm_vcpu_ioctl이 호출하는 **x86-specific 핸들러** 입니다. **vcpu_run 호출 전후의 게스트 실행 준비/정리** 를 담당하는 함수입니다. 함수 진입 시 vCPU를 현재 호스트 CPU에 활성화한 다음, 특수 케이스를 처리하고 게스트 실행 루프로 들어갑니다. 종료 시에는 게스트 FPU를 저장하고 호스트 FPU를 복원한 후 vCPU를 비활성화합니다.

```c
/* Called within kvm->srcu read side.  */
static int vcpu_run(struct kvm_vcpu *vcpu)
{
	int r;

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->arch.l1tf_flush_l1d = true;

	for (;;) {
		/*
		 * If another guest vCPU requests a PV TLB flush in the middle
		 * of instruction emulation, the rest of the emulation could
		 * use a stale page translation. Assume that any code after
		 * this point can start executing an instruction.
		 */
		vcpu->arch.at_instruction_boundary = false;
		if (kvm_vcpu_running(vcpu)) {
			r = vcpu_enter_guest(vcpu);
		} else {
			r = vcpu_block(vcpu);
		}

		if (r <= 0)
			break;

		kvm_clear_request(KVM_REQ_UNBLOCK, vcpu);
		if (kvm_xen_has_pending_events(vcpu))
			kvm_xen_inject_pending_events(vcpu);

		if (kvm_cpu_has_pending_timer(vcpu))
			kvm_inject_pending_timer_irqs(vcpu);

		if (dm_request_for_irq_injection(vcpu) &&
			kvm_vcpu_ready_for_interrupt_injection(vcpu)) {
			r = 0;
			vcpu->run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
			++vcpu->stat.request_irq_exits;
			break;
		}

		if (__xfer_to_guest_mode_work_pending()) {
			kvm_vcpu_srcu_read_unlock(vcpu);
			r = xfer_to_guest_mode_handle_work(vcpu);
			kvm_vcpu_srcu_read_lock(vcpu);
			if (r)
				return r;
		}
	}

	return r;
}
```
`vcpu_run` 함수는 커널 측에서 게스트를 실행하는 루프의 본체를 담당하는 함수입니다. `kvm_vcpu_running` 함수는 **vCPU가 실행 가능한 상태인지** 확인하는 함수로, mp_state(MultiProcessor state)가 RUNNABLE 해야 하고, APF(Async Page Fault)로 정지 상태가 아니여야 true를 반환합니다. vCPU가 실행 가능한 상태일 때 `vcpu_enter_guest`로 게스트를 실행하고 **r <= 0** 인 경우 루프를 빠져나가 userspace 처리(PIO/MMIO/SHUTDOWN)나 에러 처리를 수행합니다. `r > 0`이면 즉시 게스트로 재진입합니다. 

```c
/*
 * Called within kvm->srcu read side.
 * Returns 1 to let vcpu_run() continue the guest execution loop without
 * exiting to the userspace.  Otherwise, the value will be returned to the
 * userspace.
 * 함수 안에서 vcpu->kvm의 RCU-protected 자료구조에 접근하기 때문에, 호출자가 미리 lock을 잡아줘야 안전하다는 뜻입니다. 그리고 vcpu_run 함수가 for 루프를 계속 돌게 하려면 1을 반환하고, 그 외의 값은 유저 스페이스로 반환된다는 뜻입니다.
 */
 static int vcpu_enter_guest(struct kvm_vcpu *vcpu)
{
    if (kvm_request_pending(vcpu)) {
        // 진입 전 vCPU에 처리 대기 중인 pending request를 처리하는 부분입니다. dirty ring 처리, EPT 루트 무효화, 게스트 시간(TSC) 갱신, MMU 페이지 테이블 동기화, EPT/TLB flush, 게스트에 NMI/SMI 주입 등이 있습니다.
    }
    
    // 인터럽트/이벤트 주입 준비
	if (kvm_check_request(KVM_REQ_EVENT, vcpu) || req_int_win ||
	    kvm_xen_has_interrupt(vcpu)) {
		++vcpu->stat.req_event;
		r = kvm_apic_accept_events(vcpu); // INIT/SIPI 처리 (INIT / SIPI: SMP 부팅에서 보조 CPU를 깨우는 IPI 시퀀스를 의미합니다). INIT IPI: 리셋 비슷한 상태로, SIPI (Startup IPI): 이 주소에서 실행 시작
		if (r < 0) {
			r = 0;
			goto out;
		}
		if (vcpu->arch.mp_state == KVM_MP_STATE_INIT_RECEIVED) { // 아직 부팅 전
			r = 1;
			goto out;
		}

		r = kvm_check_and_inject_events(vcpu, &req_immediate_exit); // 게스트에 보낼 인터럽트/예외를 VMCS에 채우기, 게스트가 인터럽트 받은 것처럼 만드는 것을 의미합니다. 
		if (r < 0) {
			r = 0;
			goto out;
		}
		if (req_int_win)
			static_call(kvm_x86_enable_irq_window)(vcpu);

		if (kvm_lapic_enabled(vcpu)) {
			update_cr8_intercept(vcpu);
			kvm_lapic_sync_to_vapic(vcpu); // virtual APIC 페이지 sync
		}
	}

    // 진입 직전 셋업
    r = kvm_mmu_reload(vcpu); // EPT 로드 보장
    preempt_disable(); // 호스트 스케줄러 양보 차단
    static_call(kvm_x86_prepare_switch_to_guest)(vcpu); // vendor specific (TDX/VMX 진입 직전 작업)
    local_irq_disable(); // 호스트 IRQ 차단

    smp_store_release(&vcpu->mode, IN_GUEST_MODE); // 지금 게스트 들어감
    kvm_vcpu_srcu_read_unlock(vcpu); // SRCU lock 잠시 풀기
    smp_mb__after_srcu_read_unlock(); // 메모리 배리어

    // 게스트 진입 루프
	for (;;) {
		exit_fastpath = static_call(kvm_x86_vcpu_run)(vcpu); // TDX면 tdx_vcpu_run, 일반이면 vmx_vcpu_run. 이 함수 안에서 SEAMCALL/VMENTER를 발사하고 TD/게스트를 실행합니다.
		if (likely(exit_fastpath != EXIT_FASTPATH_REENTER_GUEST))
			break; 

        // exit_fastpath == EXIT_FASTPATH_REENTER_GUEST: 게스트를 아주 빠르게 재진입
		if (kvm_lapic_enabled(vcpu))
			static_call_cond(kvm_x86_sync_pir_to_irr)(vcpu);

		if (unlikely(kvm_vcpu_exit_request(vcpu))) {
			exit_fastpath = EXIT_FASTPATH_EXIT_HANDLED;
			break;
		}

		/* Note, VM-Exits that go down the "slow" path are accounted below. */
		++vcpu->stat.exits;
	}

    // 진입 후 cleanup
    vcpu->arch.last_vmentry_cpu = vcpu->cpu;
	vcpu->arch.last_guest_tsc = kvm_read_l1_tsc(vcpu, rdtsc());

	vcpu->mode = OUTSIDE_GUEST_MODE; // 게스트 모드 해제
	smp_wmb();

    // exit 핸들러
    guest_timing_exit_irqoff();
	local_irq_enable();
	preempt_enable();

	kvm_vcpu_srcu_read_lock(vcpu);

	if (unlikely(prof_on == KVM_PROFILING)) {
		unsigned long rip = kvm_rip_read(vcpu);
		profile_hit(KVM_PROFILING, (void *)rip);
	}

	if (unlikely(vcpu->arch.tsc_always_catchup))
		kvm_make_request(KVM_REQ_CLOCK_UPDATE, vcpu);

	if (vcpu->arch.apic_attention)
		kvm_lapic_sync_from_vapic(vcpu);

	r = static_call(kvm_x86_handle_exit)(vcpu, exit_fastpath); // vendor specific exit handler로, TDX면 tdx_handle_exit, 일반이면 vmx_handle_exit
	return r;
```
`vcpu_enter_guest` 함수는 게스트 진입 사이클을 다루고 있는 함수입니다. `vcpu_run` 루프가 매 iteration마다 호출됩니다. 함수의 전체적인 구조는 다음과 같습니다.

1. pending request 처리
- 다른 스레드/이벤트가 보낸 `KVM_REQ_*` 비트 다 처리
- TLB flush, MMU sync, NMI/SMI/SHUTDOWN 등
- 일부는 즉시 r 반환하고 진입 안 함

2. 인터럽트/예외 주입 준비
- kvm_check_and_inject_events
- VMCS의 VM-Entry Interruption-Info field에 채움
- vmlaunch 직후 **CPU가 게스트 IDT로 자동 dispatch**

3. 진입 직전 셋업
- kvm_mmu_reload
- preempt_disable
- kvm_X86_prepare_switch_to_guest
- local_irq_disable
- mode = IN_GUEST_MODE
- srcu_read_unlock
- 마지막 abort 검사 (kvm_vcpu_exit_request)

4. 실제 게스트 진입
- for(;;) 루프 돌면서 fastpath의 경우 즉시 vmenter 다시 하기

5. 진입 후 cleanup
- debug register 복원
- mode = OUTSIDE_GUEST_MODE
- kvm_X86_handle_exit_irqoff (IRQ off 상태 처리)
- host IRQ 한 번 처리 (local_irq_enable + disable)
- preempt_enable, srcu_read_lock

6. exit handler
- r = static_call(kvm_x86_handle_exit)(vcpu, exit_*)
- vendor specific (TDX는 tdx_handle_exit)

`kvm-intel.ko` 모듈이 로드가 되면 `kvm_ops_update()` 함수가 호출되며 **kvm_x86_ops로 memcpy 한 후 각 필드를 static_call 사이트에 패치** 합니다. 이후 **모든 static_call(kvm_x86_xxx) 호출이 vt_xxx 함수로 direct call** 되게 됩니다.

```c
static fastpath_t vt_vcpu_run(struct kvm_vcpu *vcpu)
{
	if (is_td_vcpu(vcpu))
		return tdx_vcpu_run(vcpu);

	return vmx_vcpu_run(vcpu);
}
```
`vt_vcpu_run` 함수는 Intel KVM 모듈의 vCPU 실행 dispatcher 역할을 하는 함수입니다. `vm_type`을 보고 KVM_X86_TDX_VM이면 **tdx_vcpu_run** 함수가 호출됩니다.

```c
fastpath_t tdx_vcpu_run(struct kvm_vcpu *vcpu)
{
    // 사전 검증
	struct vcpu_tdx *tdx = to_tdx(vcpu); // kvm_vcpu -> vcpu_tdx 컨테이너 캐스팅 (TDX 전용 상태 구조체)

	if (unlikely(!tdx->initialized)) // TDH.VP.INIT SEAMCALL 끝났는지 확인
		return -EINVAL;
	if (unlikely(vcpu->kvm->vm_bugged)) { // VM이 망가진 상태면 그냥 fail
		tdx->exit_reason.full = TDX_NON_RECOVERABLE_VCPU;
		return EXIT_FASTPATH_NONE;
	}

    // Posted Interrupt 강제 self-IPI. pi_desc의 ON 비트가 켜져있으면 TD에 보낼 인터럽트가 있다는 뜻. TDX는 호스트가 직접 게스트에 인터럽트 주입을 못하고 자기 자신에게 IPI 쏘면 PI hardware가 TD entry 할 때 처리
	trace_kvm_entry(vcpu); 

	if (pi_test_on(&tdx->pi_desc)) {
		apic->send_IPI_self(POSTED_INTR_VECTOR);

		kvm_wait_lapic_expire(vcpu);
	}

	tdx_vcpu_enter_exit(tdx); // 실제 TD 진입/탈출. __seamcall_saved_ret -> TDH.VP.ENTER SEAMCALL -> ... 

    // 호스트 상태 복원
	tdx_user_return_update_cache(vcpu); // user-return MSR cache 동기화
	perf_restore_debug_store();  // perf DS 복원 (게스트가 건드릴 수 있는 영역)
	tdx_restore_host_xsave_state(vcpu);
	tdx->host_state_need_restore = true; // 다음에 호스트 상태 다시 로드 필요 표시

    // Lazy register cache 무효화
	vcpu->arch.regs_avail &= ~VMX_REGS_LAZY_LOAD_SET;
	trace_kvm_exit(vcpu, KVM_ISA_VMX);

    // 인터럽트 후처리. TD에서 나온 후 미러치 인터럽트(NMI, IRQ) 정리하기
	tdx_complete_interrupts(vcpu);

    // TDVMCALL 결과를 전파하기
	if (tdx->exit_reason.basic == EXIT_REASON_TDCALL)
		tdx->tdvmcall.rcx = vcpu->arch.regs[VCPU_REGS_RCX];
	else
		tdx->tdvmcall.rcx = 0;

	return EXIT_FASTPATH_NONE;
}
```
**tdx_vcpu_run** 함수는 TD 진입/탈출 1회 사이클을 관리하는 래퍼 함수입니다. **tdx_vcpu_enter_exit(tdx)** 함수가 호출되면 본격적으로 TD로 진입을 시작합니다.

```c
static noinstr void tdx_vcpu_enter_exit(struct vcpu_tdx *tdx)
{
	struct tdx_module_args args;


    // guest mode 진입 표시
	struct kvm_vcpu *vcpu = &tdx->vcpu;

	guest_state_enter_irqoff();

	// 게스트 GPR을 args 구조체로 copy-in
	args = (struct tdx_module_args) {
		.rcx = tdx->tdvpr_pa,
#define REG(reg, REG)	.reg = vcpu->arch.regs[VCPU_REGS_ ## REG]
		REG(rdx, RDX),
		REG(r8,  R8),
		REG(r9,  R9),
		REG(r10, R10),
		REG(r11, R11),
		REG(r12, R12),
		REG(r13, R13),
		REG(r14, R14),
		REG(r15, R15),
		REG(rbx, RBX),
		REG(rdi, RDI),
		REG(rsi, RSI),
#undef REG
	};

    // SEAMCALL 호출하는 함수. 리턴값은 tdx->exit_reason.full에 저장이 되고, VMX exit reason 인코딩을 포함합니다
	tdx->exit_reason.full = __seamcall_saved_ret(TDH_VP_ENTER, &args);

    // args에서 게스트 GPR copy-out
#define REG(reg, REG)	vcpu->arch.regs[VCPU_REGS_ ## REG] = args.reg
		REG(rcx, RCX);
		REG(rdx, RDX);
		REG(r8,  R8);
		REG(r9,  R9);
		REG(r10, R10);
		REG(r11, R11);
		REG(r12, R12);
		REG(r13, R13);
		REG(r14, R14);
		REG(r15, R15);
		REG(rbx, RBX);
		REG(rdi, RDI);
		REG(rsi, RSI);
#undef REG

    // 소프트웨어 에러 검출
	WARN_ON_ONCE(!kvm_rebooting &&
		     (tdx->exit_reason.full & TDX_SW_ERROR) == TDX_SW_ERROR);

    // NMI 인라인 처리
	if ((u16)tdx->exit_reason.basic == EXIT_REASON_EXCEPTION_NMI &&
	    is_nmi(tdexit_intr_info(vcpu))) {
		kvm_before_interrupt(vcpu, KVM_HANDLING_NMI);
		vmx_do_nmi_irqoff();
		kvm_after_interrupt(vcpu);
	}
	guest_state_exit_irqoff();
}
```
시그니처에서 `noinstr`는 instrumentation을 하지 말라는 것을 나타냅니다. 인자는 `vcpu_tdx`입니다. TD 한 사이클의 SEAMCALL 호출을 맡습니다. 게스트 GPR(General Purpose Registers)은 **게스트가 실행 중에 쓰는 CPU 레지스터 값** 을 의미합니다. 게스트에서 호스트로 전환 될 때는 **CPU 레지스터 값을 메모리(vcpu->arch.regs[])에** 넣어두고, 호스트에서 게스트로 전환할 때는 **메모리에서 레지스터 값을 꺼내 CPU 레지스터에** 넣습니다. 일단 VMXdㅔ서는 KVM이 직접 어셈블리로 CPU 레지스터에 로드를 하는데, TDX는 그렇게 할 수 없으니 **TDX module에게 전달** 하면서 게스트 레지스터에 로드할 수 있게 합니다. 참고로 오고 가는 GPR 개수에 따라 호출하는 API가 달라집니다.

```c
u64 __seamcall(u64 fn, struct tdx_module_args *args);            // 단순 SEAMCALL (RAX status만 주고 받기)
u64 __seamcall_ret(u64 fn, struct tdx_module_args *args);        // SEAMCALL이 결과를 GPR로 돌려줄 때
u64 __seamcall_saved_ret(u64 fn, struct tdx_module_args *args);  // 추가로 RBX/RSI/RDI/R12-R15까지 주고 받음
```
이 어셈블리 함수들의 정의는 **seamcall.S** 에서 확인할 수 있습니다.
```
SYM_FUNC_START(__seamcall)
	TDX_MODULE_CALL host=1
SYM_FUNC_END(__seamcall)
EXPORT_SYMBOL_GPL(__seamcall);

SYM_FUNC_START(__seamcall_ret)
	TDX_MODULE_CALL host=1 ret=1
SYM_FUNC_END(__seamcall_ret)
EXPORT_SYMBOL_GPL(__seamcall_ret);

SYM_FUNC_START(__seamcall_saved_ret)
	TDX_MODULE_CALL host=1 ret=1 saved=1
SYM_FUNC_END(__seamcall_saved_ret)
EXPORT_SYMBOL_GPL(__seamcall_saved_ret);
```
**TDX_MODULE_CALL** 은 tdxcall.S에 정의된 어셈블리 코드 템플릿입니다. 컴파일 과정에서 seamcall.S의 매크로 호출이 tdxcall.S의 어셈블리 코드로 치환됩니다. tdxcall.S은 **.macro TDX_MODULE_CALL host:req ret=0 saved=0** 부터 **.endm** 까지 어셈블리 코드로 이루어져 있으며, `host:req, ret=0, saved=0`은 host 값은 명시되어야 하고, 나머지 두 파라미터의 기본값은 0으로 간주한다는 의미입니다. 
```
.if \host && \ret && \saved
	pushq	%rbp
	movq	%rsp, %rbp
.else
	FRAME_BEGIN
.endif
```
이때 `\host`는 host=1일 때 if 블럭을 적용한다는 의미입니다. 큰 골격으로 봤을 때 매크로는 파라비터별 케이스를 구분하면서 **준비 - seamcalll/tdcall - 회수 - 복원/정리** 구조를 구성하고 있습니다. 파라미터의 경우, host가 1이면 seamcall, 0이면 tdcall을 호출한다거나 saved=1이면 추가 GPR 활용, callee-saved 보존 작업을 추가로 하는 것 등을 의미합니다.

이제 추가된 공격 코드를 다시 살펴보겠습니다. `seamcall.S`에 새로 추가된 파라미터와 API를 함수를 확인할 수 있습니다. 
```c
/*
 * __seamcall_saved_ret_tdxstep() - Host-side interface functions to SEAM software
 * (the P-SEAMLDR or the TDX module), with saving output registers to the
 * 'struct tdx_module_args' used as input.
 *
 * __seamcall_saved_ret_tdxstep() function ABI:
 *
 * @fn   (RDI)  - SEAMCALL Leaf number, moved to RAX
 * @args (RSI)  - struct tdx_module_args for input and output
 * @args (RDX)  - timings_array   : Index 0 rdtsc timestamp directly after seamcall. Index 1 value we write to MSR_IA32_TSC_DEADLINE. We need
 * @args (RCX)  - apic_tsc_offset : if nonzero, write rdtsc() + apic_tsc_offset to MSR_IA32_TSC_DEADLINE in order to start the apic timer
 *
 * All registers in @args are used as input/output registers.
 *
 * Return (via RAX) TDX_SEAMCALL_VMFAILINVALID if the SEAMCALL itself
 * fails, or the completion status of the SEAMCALL leaf function.
 */
SYM_FUNC_START(__seamcall_saved_ret_tdxstep)
	TDX_MODULE_CALL host=1 ret=1 saved=1 tdxstep=1
SYM_FUNC_END(__seamcall_saved_ret_tdxstep)
EXPORT_SYMBOL_GPL(__seamcall_saved_ret_tdxstep)
```
새로 추가된 파라미터는 `tdxstep`으로 tdxstep=1이면 공격하는 것을 나타냅니다. 그리고 기존 레지스터 중 사용하지 않던 두 레지스터 rdx, rcx를 이용하여 추가 정보를 전달합니다. 
- rdx: `timings` - 호출자가 미리 할당한 배열의 포인터로, 인덱스 0에는 seamcall 직후 읽은 rdtsc값, 1에는 MSR에 쓴 deadline 값이 들어갑니다. 
- rcx: `apic_tsc_offset` - APIC 타이머를 언제 발사시킬지 결정하는 단방향 설정값으로, nonzero라면 `rdtsc() + apic_tsc_offset`을 계산하여 **MSR_IA32_TSC_DEALINE** 에 기록함으로써 TSC-dealine 모드로 미리 설정된 APIC 타이머를 장전합니다. 



### APIC export

### ioctl 진입점 + 전역 config

### SEAMCALL 패스 (TD enter/exit)

### 페이지 폴트 패스

### teardown

## 실제 세팅
1. 6.8.0 canonical/intel 커널 소스코드 다운받기
```
dpkg-source -x linux-intel-opt_6.5.0-1003.3.dsc 
```

2. 커널 패치 포팅

3. 빌드 및 deb 패키징

4. 커널 설치할 환경에서 dpkg 및 재부팅 순서 조정
```
sudo dpkg -i linux-image-6.5.3-its-tdx_6.5.3-2_amd64.deb linux-headers-6.5.3-its-tdx_6.5.3-2_amd64.deb

sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux 6.5.3-its-tdx"
sudo reboot
```

이제 TD에 들어갈 이미지를 구성해야 합니다. 일단 아티팩트의 `our_run_td.sh`에서 사용하고 있는 버전을 그대로 사용하고자 합니다: **tdx-guest-ubuntu-23.10.qcow2**

다만 23.10 버전 이미지를 만들려면 `create-td-image.sh` 스크립트를 좀 수정해야 합니다. 23.10은 EOL이라 공식 지원 버전에서 벗어났기 때문입니다. 따라서 클라우드 이미지 다운로드 경로를 **old-releases.ubuntu.com** 으로 바꿔야 합니다. 그리고 스크립트를 사용할 때는 저 스크립트 외에도 tdx 폴더에 존재하는 여러 파일들이 필요합니다. 

<details>
<summary> 수정된 스크립트 (338 ~ 332 line 추가, 335 ~ 345 line 추가) </summary>

```bash
#!/bin/bash

# This source code is a modified copy of https://github.com/intel/tdx-tools.git
# See LICENSE.apache file for original license information.

# This file is part of Canonical's TDX repository which includes tools
# to setup and configure a confidential computing environment
# based on Intel TDX technology.
# See the LICENSE file in the repository for the license text.

# Copyright 2024 Canonical Ltd.
# SPDX-License-Identifier: GPL-3.0-only

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3,
# as published by the Free Software Foundation.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranties
# of MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.

# This script will create a TDX guest image (qcow2 format) from a cloud
# image that is released at : https://cloud-images.ubuntu.com
# The cloud image is released as qcow3/qcow2 image (with .img suffix)
# The image comes with only 2 partitions:
#   - rootfs (~2G -> /)
#   - BIOS Boot (4M)
#   - EFI partition (~100M -> /boot/efi/ partition)
#   - Ext boot (/boot/ partition)
#
# As first step, we will resize the rootfs partition to a bigger size
# As second step, we will boot up the image to run cloud-init (using virtinst)
# and finally, we use virt-customize to copy in and run TDX setup script
#
# TODO : ask cloud init to run the TDX setup script

# User can tune the current script by providing arguments to the script
# or setting following environment variables:

# UBUNTU_VERSION: the ubuntu version (24.04, 24.10, ...)
# GUEST_USER: the username in the image
# GUEST_PASSWORD: the user password in the image
# GUEST_HOSTNAME: the guest hostname

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# source config file
if [ -f ${SCRIPT_DIR}/../../setup-tdx-config ]; then
    source ${SCRIPT_DIR}/../../setup-tdx-config
fi

LOGFILE=/tmp/tdx-guest-setup.txt
FORCE_RECREATE=false
TMP_GUEST_IMG_PATH="/tmp/tdx-guest-tmp.qcow2"
SIZE=100
GUEST_USER=${GUEST_USER:-"tdx"}
GUEST_PASSWORD=${GUEST_PASSWORD:-"123456"}
GUEST_HOSTNAME=${GUEST_HOSTNAME:-"tdx-guest"}

ok() {
    echo -e "\e[1;32mSUCCESS: $*\e[0;0m"
}

error() {
    echo -e "\e[1;31mERROR: $*\e[0;0m"
    cleanup
    exit 1
}

warn() {
    echo -e "\e[1;33mWARN: $*\e[0;0m"
}

info() {
    echo -e "\e[0;33mINFO: $*\e[0;0m"
}

check_tool() {
    [[ "$(command -v $1)" ]] || { error "$1 is not installed" 1>&2 ; }
}

# On Ubuntu noble 24.04
# if passt is install and virt-customize runs as root, virt-customize
# will fail, this is a work-around for this issue
# Furthermore, we see some instability to reach ubuntu archive when
# passt is used on 24.10, so for now, we decide to remove it
# for both 24.04 and 24.10
workaround_passt() {
    if command -v passt 2>&1 > /dev/null ; then
       echo "You have the package passt installed, this will prevent"
       echo "  the script to work properly. This package has to be removed:"
       apt autoremove passt
    fi
}

usage() {
    cat <<EOM
Usage: $(basename "$0") [OPTION]...
  -h                        Show this help
  -f                        Force to recreate the output image
  -n                        Guest host name, default is "tdx-guest"
  -u                        Guest user name, default is "tdx"
  -p                        Guest password, default is "123456"
  -s                        Specify the size of guest image
  -v                        Ubuntu version (24.04, 25.04)
  -o <output file>          Specify the output file, default is tdx-guest-ubuntu-<version>.qcow2.
                            Please make sure the suffix is qcow2. Due to permission consideration,
                            the output file will be put into /tmp/<output file>.
EOM
}

process_args() {
    while getopts "v:o:s:n:u:p:r:fch" option; do
        case "$option" in
        o) GUEST_IMG_PATH=$(realpath "$OPTARG") ;;
        s) SIZE=${OPTARG} ;;
        n) GUEST_HOSTNAME=${OPTARG} ;;
        u) GUEST_USER=${OPTARG} ;;
        p) GUEST_PASSWORD=${OPTARG} ;;
        f) FORCE_RECREATE=true ;;
        v) UBUNTU_VERSION=${OPTARG} ;;
        h)
            usage
            exit 0
            ;;
        *)
            echo "Invalid option '-${OPTARG}'"
            usage
            exit 1
            ;;
        esac
    done

    if [[ -z "${UBUNTU_VERSION}" ]]; then
        error "Please specify the ubuntu release by setting UBUNTU_VERSION or passing it via -v"
    fi

    # generate variables
    CLOUD_IMG="ubuntu-${UBUNTU_VERSION}-server-cloudimg-amd64.img"
    CLOUD_IMG_PATH=$(realpath "${SCRIPT_DIR}/${CLOUD_IMG}")

    # output guest image, set it if user does not specify it
    if [[ -z "${GUEST_IMG_PATH}" ]]; then
        if [[ "${TDX_SETUP_INTEL_KERNEL}" == "1" ]]; then
	    GUEST_IMG_PATH=$(realpath "tdx-guest-ubuntu-${UBUNTU_VERSION}-intel.qcow2")
        else
	    GUEST_IMG_PATH=$(realpath "tdx-guest-ubuntu-${UBUNTU_VERSION}-generic.qcow2")
        fi
    fi

    if [[ "${CLOUD_IMG_PATH}" == "${GUEST_IMG_PATH}" ]]; then
        error "Please specify a different name for guest image via -o"
    fi

    if [[ ${GUEST_IMG_PATH} != *.qcow2 ]]; then
        error "The output file should be qcow2 format with the suffix .qcow2."
    fi
}

download_image() {
    # Get the checksum file first
    if [[ -f ${SCRIPT_DIR}/"SHA256SUMS" ]]; then
        rm ${SCRIPT_DIR}/"SHA256SUMS"
    fi

    OFFICIAL_UBUNTU_IMAGE="https://cloud-images.ubuntu.com/releases/${UBUNTU_VERSION}/release/"
    wget "${OFFICIAL_UBUNTU_IMAGE}/SHA256SUMS" -O ${SCRIPT_DIR}/"SHA256SUMS"

    while :; do
        # Download the cloud image if not exists
        if [[ ! -f ${CLOUD_IMG_PATH} ]]; then
            wget -O ${CLOUD_IMG_PATH} ${OFFICIAL_UBUNTU_IMAGE}/${CLOUD_IMG}
        fi

        # calculate the checksum
        download_sum=$(sha256sum ${CLOUD_IMG_PATH} | awk '{print $1}')
        found=false
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" == *"$CLOUD_IMG"* ]]; then
                if [[ "${line%% *}" != ${download_sum} ]]; then
                    echo "Invalid download file according to sha256sum, re-download"
                    rm ${CLOUD_IMG_PATH}
                else
                    ok "Verify the checksum for Ubuntu cloud image."
                    return
                fi
                found=true
            fi
        done < ${SCRIPT_DIR}/"SHA256SUMS"
        if [[ $found != "true" ]]; then
            echo "Invalid SHA256SUM file"
            exit 1
        fi
    done
}

create_guest_image() {
    if [ ${FORCE_RECREATE} = "true" ]; then
        rm -f ${CLOUD_IMG_PATH}
    fi

    download_image

    # this image will need to be customized both by virt-customize and virt-install
    # virt-install will interact with libvirtd and if the latter runs in normal user mode
    # we have to make sure that guest image is writable for normal user
    install -m 0777 ${CLOUD_IMG_PATH} ${TMP_GUEST_IMG_PATH}
    if [ $? -eq 0 ]; then
        ok "Copy the ${CLOUD_IMG} => ${TMP_GUEST_IMG_PATH}"
    else
        error "Failed to copy ${CLOUD_IMG} to /tmp"
    fi

    resize_guest_image
}

# To resize the guest image
# 1) we add additional space to the qcow image using qemu-img tool
# 2) we extend (using growpart) the partition sda1 to fill empty space until end of disk
#    since sda1 is the last partition, it will take all space we previously added
# 3) we resize the file system to cover all partition space
#
# NB: We should not use static name for the disk device (sda) because it can
# change on boot (e.g., the main disk might be named sdb). Using sda naming can cause failure
# of the resizeing operation from time to time.
# Instead, we access the disk by ID:
#
# /dev/disk/by-id:
# total 0
# lrwxrwxrwx 1 0 0  9 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_appliance -> ../../sdb
# lrwxrwxrwx 1 0 0  9 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_hd0 -> ../../sda
# lrwxrwxrwx 1 0 0 10 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_hd0-part1 -> ../../sda1
# lrwxrwxrwx 1 0 0 11 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_hd0-part14 -> ../../sda14
# lrwxrwxrwx 1 0 0 11 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_hd0-part15 -> ../../sda15
# lrwxrwxrwx 1 0 0 11 Sep  2 12:59 scsi-0QEMU_QEMU_HARDDISK_hd0-part16 -> ../../sda16
resize_guest_image() {
    qemu-img resize ${TMP_GUEST_IMG_PATH} +${SIZE}G
    virt-customize -a ${TMP_GUEST_IMG_PATH} \
        --no-network \
        --run-command 'growpart /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_hd0 1' \
        --run-command 'resize2fs /dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_hd0-part1' \
        --run-command 'systemctl mask pollinate.service'
    if [ $? -eq 0 ]; then
        ok "Resize the guest image to ${SIZE}G"
    else
        error "Failed to resize guest image to ${SIZE}G"
    fi
}

config_cloud_init_cleanup() {
  virsh shutdown tdx-config-cloud-init &> /dev/null
  sleep 1
  virsh destroy tdx-config-cloud-init &> /dev/null
  virsh undefine tdx-config-cloud-init &> /dev/null
}

apply_cloud_init_conf() {
  virt_type=$1
  virt-install --debug --memory 4096 --vcpus 4 --name tdx-config-cloud-init \
     --disk ${TMP_GUEST_IMG_PATH} \
     --disk /tmp/ciiso.iso,device=cdrom \
     --os-variant ubuntu${UBUNTU_VERSION} \
     --virt-type ${virt_type} \
     --graphics none \
     --import \
     --wait=12 &>> ${LOGFILE}
}


config_cloud_init() {
    pushd ${SCRIPT_DIR}/cloud-init-data
    [ -e /tmp/ciiso.iso ] && rm /tmp/ciiso.iso
    cp user-data.template user-data
    cp meta-data.template meta-data

    # configure the user-data
    cat <<EOT >> user-data

user: $GUEST_USER
password: $GUEST_PASSWORD
chpasswd: { expire: False }
EOT

    # configure the meta-dta
    cat <<EOT >> meta-data

local-hostname: $GUEST_HOSTNAME
EOT

    info "Generate configuration for cloud-init..."
    genisoimage -output /tmp/ciiso.iso -volid cidata -joliet -rock user-data meta-data
    info "Apply cloud-init configuration with virt-install..."
    info "(Check logfile for more details ${LOGFILE})"
    popd

    apply_cloud_init_conf kvm
    RET=$?
    if [ ${RET} -eq 0 ]; then
        ok "Apply cloud-init configuration with virt-install"
        sleep 1
    else
        # if the failure is caused by lack of KVM support
        # try qemu virt type
        if [ ! -f /dev/kvm ]; then
            apt install --yes qemu-system-x86
            apply_cloud_init_conf qemu
            RET=$?
        fi
    fi
    if [ ${RET} -ne 0 ]; then
        warn "Please increase wait time(--wait=12) above and try again..."
        error "Failed to configure cloud init. Please check logfile \"${LOGFILE}\" for more information."
    fi

    config_cloud_init_cleanup
}

fix_eol_apt_sources() {
    # Ubuntu EOL releases are moved from archive.ubuntu.com to old-releases.ubuntu.com
    # Ubuntu 23.10+ uses DEB822 format at /etc/apt/sources.list.d/ubuntu.sources
    virt-customize -a ${TMP_GUEST_IMG_PATH} \
        --run-command "sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true" \
        --run-command "sed -i 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true" \
        --run-command "sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true" \
        --run-command "sed -i 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true"
    if [ $? -eq 0 ]; then
        ok "Updated apt sources to old-releases.ubuntu.com for EOL release"
    else
        error "Failed to update apt sources"
    fi
}

setup_guest_image() {
    info "Run setup scripts inside the guest image. Please wait (can take > 10 minutes) ..."

    # For EOL Ubuntu releases, redirect apt sources to old-releases.ubuntu.com
    local eol_versions=("23.10" "23.04" "22.10" "21.10" "21.04" "20.10")
    for eol_ver in "${eol_versions[@]}"; do
        if [[ "${UBUNTU_VERSION}" == "${eol_ver}" ]]; then
            info "Ubuntu ${UBUNTU_VERSION} is EOL, fixing apt sources..."
            fix_eol_apt_sources
            break
        fi
    done

    virt-customize -a ${TMP_GUEST_IMG_PATH} \
       --mkdir /tmp/tdx/ \
       --copy-in ${SCRIPT_DIR}/setup.sh:/tmp/tdx/ \
       --copy-in ${SCRIPT_DIR}/../../setup-tdx-guest.sh:/tmp/tdx/ \
       --copy-in ${SCRIPT_DIR}/../../setup-tdx-common:/tmp/tdx \
       --copy-in ${SCRIPT_DIR}/../../setup-tdx-config:/tmp/tdx \
       --copy-in ${SCRIPT_DIR}/../../attestation/:/tmp/tdx \
       --copy-in ${SCRIPT_DIR}/../../tests/lib/tdx-tools/:/tmp/tdx \
       --run-command "/tmp/tdx/setup.sh"
    if [ $? -eq 0 ]; then
        ok "Run setup scripts inside the guest image"
    else
        error "Failed to setup guest image"
    fi
}

cleanup() {
    if [[ -f ${SCRIPT_DIR}/"SHA256SUMS" ]]; then
        rm ${SCRIPT_DIR}/"SHA256SUMS"
    fi
    info "Cleanup!"
}

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# remove log file to avoid `permission denied` error if the file already exists and owned by a different user
# recently, on Ubuntu and Debian, the syctl variable fs.protected_regular is set to 2
# that will prevent root from writing to file owned by a different user
rm -f ${LOGFILE}
echo "=== tdx guest image generation === " > ${LOGFILE}

# sanity cleanup
config_cloud_init_cleanup

# install required tools
apt install --yes qemu-utils libguestfs-tools virtinst genisoimage libvirt-daemon-system &>> ${LOGFILE}

# to allow virt-customize to have name resolution, dhclient should be available
# on the host system. that is because virt-customize will create an appliance (with supermin)
# from the host system and will collect dhclient into the appliance
apt install --yes isc-dhcp-client &>> ${LOGFILE}

check_tool qemu-img
check_tool virt-customize
check_tool virt-install
check_tool genisoimage
workaround_passt

info "Installation of required tools"

process_args "$@"

create_guest_image

config_cloud_init

setup_guest_image

cleanup

mv ${TMP_GUEST_IMG_PATH} ${GUEST_IMG_PATH}
chmod a+rw ${GUEST_IMG_PATH}

ok "TDX guest image : ${GUEST_IMG_PATH}"
```
