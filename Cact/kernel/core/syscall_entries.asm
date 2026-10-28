[BITS 64]
%include "context.inc"

global syscall_entry

extern syscall_handler
extern syscall_esp0

section .text

; ---------------------------------------------------------------------------
; Fast syscall entry (the IA32_LSTAR target of the `syscall` instruction).
;
; User convention (set by the CactLib stub rebuilt in Phase 6 of
; PORTING-x86_64.md):
;   rax = syscall number
;   rdi = arg1, rsi = arg2, rdx = arg3
;   rcx = return RIP   (CPU-saved; `syscall` writes it there)
;   r11 = user RFLAGS  (CPU-saved)
;   rsp = user RSP     (`syscall` does NOT switch stacks)
;
; FMASK clears IF (and DF) on entry, so the user stack is safe until we switch
; to this CPU's kernel entry stack.  The entry then builds a `struct
; context_frame` (byte-identical to `struct syscall_frame`) on that stack,
; dispatches, and returns through the same epilogue as an exception stub:
; restore the registers, drop int_no/err_code, `iretq`.  IRET is used rather
; than SYSRET because SYSRET's selector arithmetic (SS = CS - 8) does not match
; this GDT's user-code-then-user-data ordering; the round trip is otherwise
; identical and IRET keeps one return path for syscalls, faults and IRQs.
; ---------------------------------------------------------------------------
syscall_entry:
    ; Borrow one word of user stack to hold the syscall number while we find
    ; this CPU's kernel stack; nothing reads it back except us, and the user
    ; stack pointer is restored on return.  r10 is spare in our 3-argument ABI.
    mov r10, rsp                    ; r10 = user RSP
    push rax                        ; [user_rsp - 8] = number
    str ax                          ; AX = TR selector = (TSS_SLOT + 2*cpu) << 3
    shr eax, 3
    sub eax, 5                      ; drop TSS_SLOT
    shr eax, 1                      ; two GDT slots per 64-bit TSS -> cpu index
    mov rsp, [syscall_esp0 + rax*8] ; this CPU's kernel entry stack (per-CPU)
    mov rax, [r10 - 8]              ; reload the number

    ; Build the frame, lowest address last: the pushes run in reverse field
    ; order so the last one lands as `r15`, the frame's first field.
    push qword 0x23                 ; ss   (user data | RPL3)
    push r10                        ; rsp  (user)
    push r11                        ; rflags (user; CPU-saved into r11)
    push qword 0x1B                 ; cs   (user code | RPL3)
    push rcx                        ; rip  (user; CPU-saved into rcx)
    push qword 0                    ; err_code (unused for a syscall)
    push qword 0                    ; int_no
    push rdi
    push rsi
    push rdx
    push rcx
    push rax
    push r8
    push r9
    push r10
    push r11
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Long mode ignores ds/es, so there is no kernel data segment to load.
    sti                             ; on the kernel stack now — the frame is whole
    mov rdi, rsp                    ; arg: struct context_frame*
    call syscall_handler

    ISR_RESTORE
    add rsp, 16                     ; drop int_no / err_code
    iretq
