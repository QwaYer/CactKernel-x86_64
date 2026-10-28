[BITS 64]

; ---------------------------------------------------------------------------
; 64-bit context switch and first-entry trampolines.
;
; `switch_to` saves only the callee-saved registers — r15, r14, r13, r12, rbp
; and rbx — because the kernel is compiled with the SysV ABI, so every other
; register is already dead at the call boundary.  They are pushed in the order
; that makes the saved area byte-identical to the first six fields of
; `struct context_frame` (Cact/kernel/proc/task.h): r15 lowest, rbx highest.
; A fork child's frame reuses them for exactly that reason.
;
; A brand-new task's kernel stack holds, from its saved stack pointer upwards:
;
;     [r15 r14 r13 r12 rbp rbx] [return address] [task-specific frame]
;
; so `ret` lands in one of the three trampolines below, each of which expects
; the frame its own kind of task was built with.
; ---------------------------------------------------------------------------

global switch_to
global switch_paging
global kernel_task_trampoline
global user_task_trampoline
global fork_task_trampoline

extern sched_park_prev

section .text

; void switch_to(uint64_t* prev_rsp_slot, uint64_t new_rsp)
;
; `prev_rsp_slot` is `&prev->esp`, which is also `prev` itself because `esp` is
; field 0 of `struct task_struct`; `new_rsp` is `next->esp`.  `sched_park_prev`
; runs on the *incoming* stack, after the switch is committed, so that the
; outgoing task cannot be popped and resumed on a stale stack by another CPU.
switch_to:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp          ; commit: save the outgoing stack pointer
    mov rsp, rsi            ; switch to the incoming stack
    mov r15, rsp            ; hold the frame base across the call below
    push rdi                ; arg: prev (== &prev->esp)
    and rsp, -16            ; SysV: rsp must be 16-aligned at the call; a kernel
                            ; stack from the heap is only 8-aligned
    call sched_park_prev    ; prev is parked now that the switch is committed
    mov rsp, r15            ; back to the incoming frame base
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; void switch_paging(uint64_t* pd)
;
; `pd` is the *physical* address of the page map to load: callers translate the
; pointer (a direct-map VA for a process map, the kernel-image VA for the
; kernel's own map) with vmm_v2p() first, because CR3 can only hold a physical
; address.  The link-base subtraction below stays as a safety net for a caller
; that hands over a kernel-image VA.
switch_paging:
    mov rax, rdi
    mov rcx, 0xFFFFFFFF80000000
    cmp rax, rcx
    jb .phys
    sub rax, rcx
.phys:
    mov cr3, rax
    ret

; First entry of a kernel task.  `switch_to`'s `ret` left the entry point on
; top of the stack; enabling interrupts here is what lets the timer preempt it.
kernel_task_trampoline:
    sti
    ret

; First entry of a user task.  The stack holds the IRETQ frame
; (rip, cs, rflags, rsp, ss) built by the task creator.
user_task_trampoline:
    mov ax, 0x23
    mov ds, ax
    mov es, ax
    swapgs                          ; kernel -> user: %gs back to the user base
    iretq

; First entry of a fork child.  A full `struct context_frame` follows the
; return address, so restore every register, drop int_no/err_code and return to
; user mode exactly as an exit stub would.
fork_task_trampoline:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rax
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    add rsp, 16
    swapgs                          ; kernel -> user: %gs back to the user base
    iretq
