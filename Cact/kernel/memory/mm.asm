[bits 64]

; Control-register helpers.  CR0/CR2/CR3 are 64-bit registers in long mode and
; only the 64-bit forms are encodable, so every access is full-width even where
; the C declaration is still pointer-width-agnostic.

global load_page_directory
global enable_paging
global read_cr2

; void load_page_directory(uint32_t* directory)
load_page_directory:
    mov cr3, rdi
    ret

; void enable_paging(void)
enable_paging:
    mov rax, cr0
    or rax, 0x80000000
    mov cr0, rax
    ret

; uintptr_t read_cr2(void)
read_cr2:
    mov rax, cr2
    ret
