[bits 64]

; I/O port access primitives — System V AMD64 calling convention.
; Port is the first argument (rdi), the written value the second (rsi); the
; `in` functions return in eax, with the upper bits zeroed so the caller sees a
; clean uint8_t/uint16_t/uint32_t.

global outl
global inl
global outb
global inb
global inw
global outw

; void outl(uint16_t port, uint32_t value)
outl:
    mov edx, edi        ; port
    mov eax, esi        ; value
    out dx, eax
    ret

; uint32_t inl(uint16_t port)
inl:
    mov edx, edi        ; port
    in eax, dx          ; 32-bit read — EAX fully overwritten
    ret

; void outb(uint16_t port, uint8_t value)
outb:
    mov edx, edi        ; port
    mov eax, esi        ; value (low byte only)
    out dx, al
    ret

; uint8_t inb(uint16_t port)
inb:
    mov edx, edi        ; port
    xor eax, eax        ; zero EAX so upper bits are clean
    in al, dx           ; 8-bit read
    ret

; uint16_t inw(uint16_t port)
inw:
    mov edx, edi        ; port
    xor eax, eax        ; zero EAX so upper bits are clean
    in ax, dx           ; 16-bit read
    ret

; void outw(uint16_t port, uint16_t value)
outw:
    mov edx, edi        ; port
    mov eax, esi        ; value (low 16 bits used)
    out dx, ax
    ret
