/* Higher half: the kernel lives at the bottom of the top 2 GiB, which is the
 * range the cmp/small immediates of the kernel code model can reach, while the
 * image itself is loaded -- and stays addressable -- at 1 MiB physical.  The
 * long-mode bootstrap in Cact/kernel/core/kernel.asm maps KERNEL_VMA -> 1 MiB
 * before it jumps here.  See PORTING-x86_64.md, decision 4.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

KERNEL_VMA = 0xFFFFFFFF80000000;
KERNEL_LMA = 1M;

SECTIONS {
    . = KERNEL_VMA + KERNEL_LMA;

    .text BLOCK(4K) : AT(ADDR(.text) - KERNEL_VMA) ALIGN(4K) {
        *(.multiboot)
        *(.text)
    }

    .rodata BLOCK(4K) : AT(ADDR(.rodata) - KERNEL_VMA) ALIGN(4K) {
        *(.rodata)
    }

    .data BLOCK(4K) : AT(ADDR(.data) - KERNEL_VMA) ALIGN(4K) {
        *(.data)
    }

    .bss BLOCK(4K) : AT(ADDR(.bss) - KERNEL_VMA) ALIGN(4K) {
        *(COMMON)
        *(.bss)
    }
}
