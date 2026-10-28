; ---------------------------------------------------------------------------
; Cact OS — x86_64 boot: Multiboot2 entry point and long-mode bootstrap
; ---------------------------------------------------------------------------
;
; GRUB leaves us in 32-bit protected mode with paging off, at the image's
; physical load address (1 MiB — see linker.ld).  Everything in .boot is linked
; at that physical address, because it is the code that builds the page tables;
; the kernel proper is linked into the top 2 GiB and becomes reachable as soon
; as those tables are live.
;
; When this file is done, three views of memory exist:
;
;   0x0000000000000000 .. 0x0000000100000000   identity map, 2 MiB pages
;   0xFFFF800000000000 .. 0xFFFF800100000000   direct map (PML4[256])
;   0xFFFFFFFF80000000 .. 0xFFFFFFFFC0000000   the first GiB, higher half
;
; The identity map (write-back below 1 GiB, uncached above, where MMIO lives)
; is what the not-yet-ported, 32-bit-era memory code still needs while early
; boot runs: it stores physical addresses and dereferences them.  The direct
; map is the same windows seen through PML4[256], so p2v() works before the
; real kernel map is built; init_paging() (build_kernel_map) then rebuilds
; both and shrinks the identity map to the boot reservation alone.

[bits 32]

MB2_MAGIC    equ 0xE85250D6
MB2_ARCH     equ 0                              ; i386 protected mode
MB2_LENGTH   equ header_end - header_start
MB2_CHECKSUM equ -(MB2_MAGIC + MB2_ARCH + MB2_LENGTH)

KERNEL_VMA   equ 0xFFFFFFFF80000000

global _start
extern init
extern __bss_start
extern __bss_end

; --------------------------------------------------------------------------
; Multiboot2 header — must sit in the first 32 KiB of the image
; --------------------------------------------------------------------------
section .multiboot progbits alloc noexec nowrite
align 8
header_start:
    dd MB2_MAGIC
    dd MB2_ARCH
    dd MB2_LENGTH
    dd MB2_CHECKSUM

    ; Information request tag
    align 8
ireq_start:
    dw 1                                         ; type = information request
    dw 0                                         ; flags
    dd ireq_end - ireq_start                     ; size
    dd 4                                         ; BASIC_MEMINFO
    dd 6                                         ; MMAP
    dd 8                                         ; FRAMEBUFFER
ireq_end:

    ; Framebuffer tag: no preferred mode.  width/height/bpp = 0 tells the
    ; bootloader to pick the mode itself (multiboot2 spec); the kernel then
    ; uses whatever geometry/format GRUB reports in the framebuffer info tag.
    align 8
fbtag_start:
    dw 5                                         ; type = framebuffer
    dw 0                                         ; flags (0 = required)
    dd fbtag_end - fbtag_start                   ; size
    dd 0                                         ; width  (0 = bootloader chooses)
    dd 0                                         ; height (0 = bootloader chooses)
    dd 0                                         ; bpp    (0 = bootloader chooses)
fbtag_end:

    ; End tag
    align 8
    dw 0
    dw 0
    dd 8
header_end:

; --------------------------------------------------------------------------
; Long-mode bootstrap (32-bit code, running at its physical address)
; --------------------------------------------------------------------------
section .boot progbits alloc exec nowrite
_start:
    cli
    cld

    ; GRUB hands over the multiboot2 magic in EAX and the information
    ; structure's address in EBX; they are passed on to init() in 64 bits.
    mov [boot_magic], eax
    mov [boot_mbi], ebx

    ; Long mode needs CPUID leaf 0x80000001 with EDX.LM set.  Without it there
    ; is nothing to fall back to, so say so on COM1 and stop.
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz .no_long_mode

    ; --- page tables -------------------------------------------------------
    ; Four-level paging, 2 MiB pages, no PSE-36 games.  pml4[0] gives the
    ; identity map of the first 4 GiB; pml4[511] puts the first GiB at
    ; 0xFFFFFFFF80000000, which is where the kernel is linked.
    mov edi, pml4
    xor eax, eax
    mov ecx, (7 * 4096) / 4
    rep stosd

    mov edi, pd_low                 ; 0..1 GiB  — write-back (RAM)
    mov eax, 0x83                   ; P | RW | PS
    xor edx, edx
    call fill_pd

    mov edi, pd_mid                 ; 1..2 GiB  — uncached (device space)
    mov eax, 0x9B                   ; P | RW | PS | PCD | PWT
    mov edx, 0x40000000
    call fill_pd

    mov edi, pd_hi1                 ; 2..3 GiB
    mov eax, 0x9B
    mov edx, 0x80000000
    call fill_pd

    mov edi, pd_hi2                 ; 3..4 GiB
    mov eax, 0x9B
    mov edx, 0xC0000000
    call fill_pd

    mov edi, pdpt_low               ; identity: 0..4 GiB
    mov eax, pd_low
    or eax, 3
    mov [edi], eax
    mov eax, pd_mid
    or eax, 3
    mov [edi + 8], eax
    mov eax, pd_hi1
    or eax, 3
    mov [edi + 16], eax
    mov eax, pd_hi2
    or eax, 3
    mov [edi + 24], eax

    mov edi, pdpt_high              ; 0xFFFFFFFF80000000 -> physical 0
    mov eax, pd_low
    or eax, 3
    mov [edi + (510 * 8)], eax

    mov edi, pml4
    mov eax, pdpt_low
    or eax, 3
    mov [edi], eax
    mov eax, pdpt_low               ; direct map for p2v(): the same windows,
    or eax, 3                       ; reachable at DIRECT_MAP_BASE.  Rebuilt by
    mov [edi + (256 * 8)], eax      ; init_paging() once the kernel map is up.
    mov eax, pdpt_high
    or eax, 3
    mov [edi + (511 * 8)], eax

    ; --- long mode ---------------------------------------------------------
    ; CR4 gains PAE (paging requires it, and it fixes the PML4 format) plus
    ; OSFXSR/OSXMMEXCPT: from here on the kernel may execute SSE, which the
    ; x86-64 SysV ABI requires for struct copies and float returns.  This is
    ; the earliest point where it is safe — the FPU/SSE state is not touched
    ; before it, and nothing has used XMM yet.
    mov eax, cr4
    or eax, (1 << 5) | (1 << 9) | (1 << 10)     ; PAE | OSFXSR | OSXMMEXCPT
    mov cr4, eax

    mov eax, pml4
    mov cr3, eax

    mov ecx, 0xC0000080                         ; IA32_EFER
    rdmsr
    or eax, (1 << 8) | (1 << 11)                ; LME | NXE
    wrmsr

    mov eax, cr0
    or eax, (1 << 31)                           ; PG (PE is already set)
    mov cr0, eax                                ; paging on: we are in long mode

    ; A GDT with a 64-bit code segment has to be in place before the far jump;
    ; init_gdt() replaces it with the real one as soon as C runs.
    lgdt [gdt64_ptr]
    jmp 0x08:long_mode_entry

.no_long_mode:
    ; No serial_init() yet, so drive COM1 by hand: writing THR is enough under
    ; QEMU, which does not care about the divisor and drains the FIFO itself.
    mov edx, 0x3F8
    mov esi, msg_no_long_mode
.next_char:
    lodsb
    test al, al
    jz .stop
    out dx, al
    jmp .next_char
.stop:
    cli
    hlt
    jmp .stop

; Fill one page directory with 512 two-megabyte mappings.
; in: EDI = table, EAX = flags, EDX = first physical address
fill_pd:
    mov ecx, 512
.loop:
    mov ebx, edx
    or ebx, eax
    mov [edi], ebx
    add edx, 0x200000
    add edi, 8
    dec ecx
    jnz .loop
    ret

; --------------------------------------------------------------------------
; 64-bit entry: still at the physical address (the low identity map makes it
; the same page as its higher-half alias), so the jump to the kernel is made
; through a full 64-bit register.
; --------------------------------------------------------------------------
[bits 64]
long_mode_entry:
    mov ax, 0x10                    ; kernel data (from the temporary GDT)
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax

    ; Zero the kernel's .bss before anything uses it (and before the stack,
    ; which lives there, is touched).
    mov rdi, [abs bss_start]
    mov rcx, [abs bss_end]
    sub rcx, rdi
    shr rcx, 3
    xor eax, eax
    rep stosq

    mov rsp, [abs kernel_stack]
    xor rbp, rbp

    mov edi, [abs boot_magic]       ; void init(uint32_t magic, uint32_t mbi)
    mov esi, [abs boot_mbi]
    mov rax, [abs kernel_entry]
    call rax

.hang:
    cli
    hlt
    jmp .hang

; --------------------------------------------------------------------------
; Data used before (and while) paging comes up
; --------------------------------------------------------------------------
section .boot.data progbits alloc noexec write
align 8
gdt64:
    dq 0x0000000000000000           ; null
    dq 0x00AF9A000000FFFF           ; 0x08 — 64-bit kernel code (L=1, D=0)
    dq 0x00AF92000000FFFF           ; 0x10 — kernel data
gdt64_end:
gdt64_ptr:
    dw gdt64_end - gdt64 - 1
    dd gdt64                        ; 32-bit base: this form is used from 32-bit mode only

boot_magic:
    dd 0
boot_mbi:
    dd 0
msg_no_long_mode:
    db 0x0A, "Cact: no long mode on this CPU", 0x0A, 0

; The things the bootstrap must reach after it switches maps.  It runs at a
; physical address and the kernel runs through the higher-half alias, and the
; kernel sits exactly 2 GiB below that address, so a 32-bit relative reference
; lands just outside the reachable range; a 64-bit pointer the linker fills has
; no such limit.
kernel_entry:
    dq init
kernel_stack:
    dq boot_stack_top
bss_start:
    dq __bss_start
bss_end:
    dq __bss_end

section .boot.bss nobits alloc noexec write
align 4096
pml4:       resb 4096
pdpt_low:   resb 4096
pdpt_high:  resb 4096
pd_low:     resb 4096
pd_mid:     resb 4096
pd_hi1:     resb 4096
pd_hi2:     resb 4096

; The bootstrap stack lives in the higher half: by the time it is used, the
; high map is up and the kernel's own C frames are addressed there too.
section .bss
align 16
boot_stack_bottom:
    resb 16384
boot_stack_top:
