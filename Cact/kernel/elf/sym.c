/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "sym.h"
#include "elf.h"
#include "task.h"
#include "validate.h"

const char* sym_resolve_addr(uint64_t addr, uint64_t* offset) {
    if (offset) *offset = 0;

    if (!current_task || current_task->is_kernel || !current_task->proc)
        return 0;

    // Only a user address can be named from the process's own ELF.  A kernel
    // address (a fault caught in ring 0, a syscall return address) has nothing
    // to do with that symbol table; matching one here used to print nonsense
    // like `_GLOBAL_OFFSET_TABLE_+0xf0103166`, because the lookup kept the last
    // symbol at or below the wrapped offset.  The full 64-bit address is tested
    // here, so the kernel's higher half is rejected rather than truncated into
    // the user window.
    if (addr < USER_SPACE_START || addr >= KERNEL_BASE)
        return 0;

    // Fall back to the cached main-binary symbol table (ET_EXEC/PIE)
    Elf64_Sym* symtab = (Elf64_Sym*)current_task->proc->exec_symtab;
    char*      strtab = current_task->proc->exec_strtab;
    int        count  = current_task->proc->exec_symtab_count;

    if (symtab && strtab && count > 0) {
        // Every CactOS image is mapped at its link-time address, so a symbol's
        // st_value is the absolute user address it names and compares against
        // `addr` directly.  Comparing it against `addr - exec_base` (as this
        // did) matched only addresses *outside* the image: a stack address came
        // back as `_GLOBAL_OFFSET_TABLE_+0xafffdf08`, while a real return
        // address inside the image resolved to nothing.
        //
        // The image's own span bounds the lookup as well — a symbol that
        // carries no size (`_start` in start.S, the GOT symbol) would otherwise
        // match any address above it.
        uint64_t img_lo = 0, img_hi = 0;
        for (int j = 0; j < count; j++) {
            uint64_t v = symtab[j].st_value;
            if (v == 0 || symtab[j].st_shndx == SHN_UNDEF) continue;
            if (img_lo == 0 || v < img_lo) img_lo = v;
            uint64_t end = v + symtab[j].st_size;
            if (end > img_hi) img_hi = end;
        }
        if (img_lo == 0 || addr < img_lo || addr >= img_hi) return 0;

        int best = -1;
        uint64_t best_val = 0;

        for (int j = 0; j < count; j++) {
            uint64_t sym_val = symtab[j].st_value;
            uint8_t st_type = ELF64_ST_TYPE(symtab[j].st_info);
            if (sym_val == 0 || sym_val > addr ||
                !(st_type == STT_FUNC || st_type == STT_NOTYPE || st_type == STT_OBJECT))
                continue;
            // When the symbol carries a size, the address has to land inside it
            // — otherwise whatever symbol happens to be last before it swallows
            // every address past the binary.
            uint64_t sym_size = symtab[j].st_size;
            if (sym_size > 0 && (addr - sym_val) >= sym_size)
                continue;
            if (best < 0 || (addr - sym_val) < (addr - best_val)) {
                best = j;
                best_val = sym_val;
            }
        }

        if (best >= 0) {
            if (offset) *offset = addr - best_val;
            return &strtab[symtab[best].st_name];
        }
    }

    return 0;
}
