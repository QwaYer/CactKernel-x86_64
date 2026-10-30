#include "elf.h"
#include "kernel.h"
#include "vfs.h"
#include "memory.h"
#include "proc_mm.h"
#include "klib.h"
#include "page_fault.h"

/* This is the exec-time ELF loader.  It executes ELF64/x86-64 images only:
 * a 64-bit kernel cannot run an ELF32 binary (the CPU would decode its 32-bit
 * instructions in long mode), and vmm_create_address_space()/the ring-3 entry
 * frames are both 64-bit.  The three `.cctk` module loaders are a separate,
 * still-32-bit ABI.
 *
 * The user VA model is still the 32-bit window: every segment must land below
 * USER_STACK_TOP (3 GiB), which is where the mmap window and user stack already
 * live.  `p_vaddr` is read as 64-bit and validated before it is narrowed, so a
 * segment claiming a higher address is rejected rather than truncated onto some
 * other page. */

/* PT_INTERP (userspace ld.so) handoff data. main_phdr points at a mapped copy
 * of the program header table (allocated by _map_image when the phdrs are not
 * covered by a PT_LOAD), so ld.so can scan it in user space just like Linux.
 * The fields are 32-bit because they feed the 32-bit auxv layout (see
 * task_exec/task_create); the address space they describe is the low window. */
typedef struct {
    uint32_t main_entry;
    uint32_t main_base;
    uint32_t main_phdr;
    uint32_t main_phnum;
    uint32_t interp_base;
} elf_interp_info_t;

/* A PT_LOAD must stay strictly below the kernel half: a segment at or above
 * USER_STACK_TOP would reach vmm_map()'s kernel-MMIO branch and be written
 * into the shared kernel page table, visible to every process.  Low addresses
 * are allowed -- vmm_map() COWs the shared low table into a private one for the
 * process -- so the only extra refusals are the NULL page and a segment wrapped
 * past the ceiling.
 *
 * No VA can shadow a kernel frame any more: the identity map is confined to the
 * boot reservation and every frame (and all device MMIO) is reached through the
 * direct map, whose PML4 entry lives in the upper half. */
static int _elf_seg_ok(uint64_t seg_start, uint64_t seg_end) {
    if (seg_end < seg_start)      return 0; /* wrapped past the address space */
    if (seg_end > USER_STACK_TOP) return 0; /* kernel half */
    if (seg_start < PAGE_SIZE)    return 0; /* would map the NULL page */
    return 1;
}

/* Loads only the PT_LOAD segments (no relocation/dynlink pass) for a file.
 * out_phdr is the user-space address of a mapped program-header table
 * (0 when the phdrs are already covered by a segment mapping). */
static int _map_image(struct vfs_node* file, uint64_t* pd,
                      proc_page_tracker_t* tracker,
                      uint64_t* out_entry, uint32_t* out_min_vaddr,
                      uint32_t* out_phdr, uint32_t* out_phnum)
{
    Elf64_Ehdr hdr;
    if (read_vfs(file, 0, sizeof(Elf64_Ehdr), (char*)&hdr) <= 0) return -1;
    if (*(uint32_t*)hdr.e_ident != ELF_MAGIC) return -1;
    if (hdr.e_ident[EI_CLASS] != ELFCLASS64) return -1;
    if (hdr.e_ident[EI_DATA]  != ELFDATA2LSB) return -1;
    if (hdr.e_ident[EI_VERSION] != EV_CURRENT) return -1;
    if (hdr.e_machine != EM_X86_64) return -1;
    if (hdr.e_phentsize < sizeof(Elf64_Phdr)) return -1;
    if ((uint32_t)hdr.e_phnum > 65535u) return -1;
    uint64_t ph_end_check = hdr.e_phoff +
                            (uint64_t)hdr.e_phnum * hdr.e_phentsize;
    if (ph_end_check > file->size) return -1;

    if (out_entry)   *out_entry   = hdr.e_entry;
    if (out_phnum)   *out_phnum   = hdr.e_phnum;
    if (out_phdr)    *out_phdr    = 0;
    if (out_min_vaddr) *out_min_vaddr = 0;

    uint64_t min_vaddr = 0xFFFFFFFFFFFFFFFFull;
    for (int i = 0; i < hdr.e_phnum; i++) {
        Elf64_Phdr ph;
        if (read_vfs(file, (uint32_t)(hdr.e_phoff + (uint64_t)i * hdr.e_phentsize),
                     sizeof(Elf64_Phdr), (char*)&ph) <= 0) return -1;
        if (ph.p_type != PT_LOAD || ph.p_memsz == 0) continue;
        if (ph.p_vaddr + ph.p_memsz < ph.p_vaddr) return -1;
        uint64_t page_start = ph.p_vaddr & ~0xFFFull;
        uint64_t page_end   = (ph.p_vaddr + ph.p_memsz + 0xFFFull) & ~0xFFFull;
        if (!_elf_seg_ok(page_start, page_end)) return -1;
        if (page_start < min_vaddr) min_vaddr = page_start;
    }
    if (min_vaddr == 0xFFFFFFFFFFFFFFFFull || min_vaddr < PAGE_SIZE) return -1;

    uint32_t phdr_bytes = (uint32_t)(ph_end_check - hdr.e_phoff);
    int phdr_covered = 0;
    uint32_t phdr_vaddr = 0;

    for (int i = 0; i < hdr.e_phnum; i++) {
        Elf64_Phdr ph;
        if (read_vfs(file, (uint32_t)(hdr.e_phoff + (uint64_t)i * hdr.e_phentsize),
                     sizeof(Elf64_Phdr), (char*)&ph) <= 0) return -1;

        if (ph.p_type == PT_LOAD && ph.p_memsz > 0) {
            if (ph.p_vaddr + ph.p_memsz < ph.p_vaddr) continue;
            if (ph.p_vaddr + ph.p_filesz < ph.p_vaddr) continue;

            uint64_t seg_start = ph.p_vaddr & ~0xFFFull;
            uint64_t seg_end   = (ph.p_vaddr + ph.p_memsz + 0xFFF) & ~0xFFFull;
            uint64_t file_end  = ph.p_vaddr + ph.p_filesz;
            if (!_elf_seg_ok(seg_start, seg_end)) return -1;

            for (uint64_t va = seg_start; va < seg_end; va += PAGE_SIZE) {
                void* phys = kalloc();
                if (!phys) { pr_err("elf: out of memory allocating segment page\n"); return -1; }
                if (proc_tracker_add(tracker, phys) < 0) {
                    free_page(phys); return -1;
                }
                uint8_t* p = (uint8_t*)phys;
                for (int k = 0; k < (int)PAGE_SIZE; k++) p[k] = 0;

                if (va < file_end) {
                    uint64_t copy_start = (va > ph.p_vaddr) ? va : ph.p_vaddr;
                    uint64_t copy_end   = ((va + PAGE_SIZE) < file_end)
                                          ? (va + PAGE_SIZE) : file_end;
                    if (copy_end > copy_start) {
                        uint32_t page_offset = (uint32_t)(copy_start - va);
                        uint64_t file_offset = ph.p_offset + (copy_start - ph.p_vaddr);
                        if (read_vfs(file, (uint32_t)file_offset,
                                     (uint32_t)(copy_end - copy_start),
                                     (char*)phys + page_offset) <= 0) return -1;
                    }
                }
                // `kalloc` returns a direct-map VA; the PTE takes the frame's
                // physical address.
                vmm_map(pd, va, vmm_v2p(phys),
                        PAGE_USER | PAGE_RW | PAGE_PRESENT);
            }

            if (!phdr_covered &&
                hdr.e_phoff >= ph.p_offset &&
                hdr.e_phoff + phdr_bytes <= ph.p_offset + ph.p_filesz) {
                phdr_covered = 1;
                phdr_vaddr   = (uint32_t)(ph.p_vaddr + (hdr.e_phoff - ph.p_offset));
            }
        }
    }

    if (!phdr_covered) {
        /* Program headers live outside every PT_LOAD (p_offset of the first
         * LOAD is 0x1000 in our fixed-address images). Map one page holding a
         * copy of the phdr table just below the lowest segment so user-space
         * ld.so can read it through AT_PHDR. */
        uint32_t page_off = (uint32_t)hdr.e_phoff & 0xFFFu;
        uint32_t copy_sz  = phdr_bytes;
        if (copy_sz > (uint32_t)(PAGE_SIZE - page_off))
            copy_sz = PAGE_SIZE - page_off;

        void* phys = kalloc();
        if (!phys) { pr_err("elf: out of memory allocating phdr page\n"); return -1; }
        if (proc_tracker_add(tracker, phys) < 0) { free_page(phys); return -1; }
        uint8_t* p = (uint8_t*)phys;
        for (int k = 0; k < (int)PAGE_SIZE; k++) p[k] = 0;
        if (copy_sz > 0)
            read_vfs(file, (uint32_t)hdr.e_phoff, copy_sz, (char*)phys + page_off);

        if (min_vaddr < PAGE_SIZE) return -1;
        uint32_t page_va = (uint32_t)min_vaddr - 0x1000u;
        // `kalloc` returns a direct-map VA; the PTE takes the physical address.
        vmm_map(pd, page_va, vmm_v2p(phys), PAGE_USER | PAGE_RW | PAGE_PRESENT);
        phdr_vaddr = page_va + page_off;
    }

    if (out_min_vaddr) *out_min_vaddr = (uint32_t)min_vaddr;
    if (out_phdr)      *out_phdr      = phdr_vaddr;
    return 0;
}

int elf_get_interp_path(const char* path, char* out, int out_max);
void* load_elf_interp(char* path, char* interp_path, uint64_t* pd,
                      proc_page_tracker_t* tracker, elf_interp_info_t* info);

void* load_elf(char* path, uint64_t* pd, proc_page_tracker_t* tracker)
{
    tracker->page_dir = pd;

    vfs_node_t *base = (path[0] == '/') ? vfs_root : vfs_root;
    struct vfs_node* file = vfs_walk_path_follow(base, path, 0);
    if (!file) {
        pr_warn("elf: file not found: %s\n", path);
        return 0;
    }

    Elf64_Ehdr hdr;
    if (read_vfs(file, 0, sizeof(Elf64_Ehdr), (char*)&hdr) <= 0) {
        pr_err("elf: cannot read ELF header from %s\n", path);
        return 0;
    }

    if (*(uint32_t*)hdr.e_ident != ELF_MAGIC) {
        pr_err("elf: bad magic 0x%08x (want 0x%08x): %s\n",
               (unsigned)*(uint32_t*)hdr.e_ident, (unsigned)ELF_MAGIC, path);
        return 0;
    }
    if (hdr.e_ident[EI_CLASS] != ELFCLASS64) {
        pr_err("elf: not 64-bit (class=%u): %s\n",
               (unsigned)hdr.e_ident[EI_CLASS], path);
        return 0;
    }
    if (hdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        pr_err("elf: not little-endian (data=%u): %s\n",
               (unsigned)hdr.e_ident[EI_DATA], path);
        return 0;
    }
    if (hdr.e_ident[EI_VERSION] != EV_CURRENT) {
        pr_err("elf: bad ident version %u: %s\n",
               (unsigned)hdr.e_ident[EI_VERSION], path);
        return 0;
    }
    if (hdr.e_machine != EM_X86_64) {
        pr_err("elf: unsupported machine %u (want %u=x86_64): %s\n",
               (unsigned)hdr.e_machine, (unsigned)EM_X86_64, path);
        return 0;
    }
    if (hdr.e_phentsize < sizeof(Elf64_Phdr)) {
        pr_err("elf: e_phentsize %u too small (min %u): %s\n",
               (unsigned)hdr.e_phentsize, (unsigned)sizeof(Elf64_Phdr), path);
        return 0;
    }
    if ((uint32_t)hdr.e_phnum > 65535u) {
        pr_err("elf: too many program headers (%u): %s\n",
               (unsigned)hdr.e_phnum, path);
        return 0;
    }
    uint64_t ph_end_check = hdr.e_phoff + (uint64_t)hdr.e_phnum * hdr.e_phentsize;
    if (ph_end_check > file->size) {
        pr_err("elf: program headers overflow file (need %u > size %u): %s\n",
               (unsigned)ph_end_check, (unsigned)file->size, path);
        return 0;
    }

    for (int i = 0; i < hdr.e_phnum; i++) {
        Elf64_Phdr ph;
        if (read_vfs(file,
                     (uint32_t)(hdr.e_phoff + (uint64_t)i * hdr.e_phentsize),
                     sizeof(Elf64_Phdr),
                     (char*)&ph) <= 0) {
            pr_err("elf: cannot read phdr %d (off %u) from %s\n",
                   i, (unsigned)(hdr.e_phoff + (uint64_t)i * hdr.e_phentsize), path);
            proc_free_pages(tracker);
            return 0;
        }

        if (ph.p_type != PT_LOAD || ph.p_memsz == 0) continue;

        if (ph.p_vaddr + ph.p_memsz < ph.p_vaddr) continue;
        if (ph.p_vaddr + ph.p_filesz < ph.p_vaddr) continue;

        uint64_t seg_start = ph.p_vaddr & ~0xFFFull;
        uint64_t seg_end   = (ph.p_vaddr + ph.p_memsz + 0xFFF) & ~0xFFFull;
        uint64_t file_end  = ph.p_vaddr + ph.p_filesz;
        if (!_elf_seg_ok(seg_start, seg_end)) {
            pr_err("elf: PT_LOAD segment %d [0x%llx,0x%llx) outside user space: %s\n",
                   i, (unsigned long long)seg_start, (unsigned long long)seg_end, path);
            proc_free_pages(tracker);
            return 0;
        }

        for (uint64_t va = seg_start; va < seg_end; va += PAGE_SIZE) {
            if (va < file_end) {
                void* phys = kalloc();
                if (!phys) {
                    pr_err("elf: out of memory allocating segment %d page\n", i);
                    proc_free_pages(tracker);
                    return 0;
                }
                if (proc_tracker_add(tracker, phys) < 0) {
                    pr_err("elf: tracker_add failed for segment %d\n", i);
                    free_page(phys);
                    proc_free_pages(tracker);
                    return 0;
                }

                uint8_t* p = (uint8_t*)phys;
                for (int k = 0; k < (int)PAGE_SIZE; k++) p[k] = 0;

                uint64_t copy_start = (va > ph.p_vaddr) ? va : ph.p_vaddr;
                uint64_t copy_end   = ((va + PAGE_SIZE) < file_end) ? (va + PAGE_SIZE) : file_end;

                if (copy_end > copy_start) {
                    uint32_t page_offset = (uint32_t)(copy_start - va);
                    uint64_t file_offset = ph.p_offset + (copy_start - ph.p_vaddr);
                    uint32_t copy_sz     = (uint32_t)(copy_end - copy_start);

                    int rd = read_vfs(file, (uint32_t)file_offset, copy_sz,
                                      (char*)phys + page_offset);
                    if (rd <= 0) {
                        pr_err("elf: read_vfs failed at off=%d sz=%d ret=%d\n",
                               (int)file_offset, (int)copy_sz, (int)rd);
                        proc_free_pages(tracker);
                        return 0;
                    }
                }

                // `kalloc` returns a direct-map VA; the PTE takes the frame's
                // physical address.
                vmm_map(pd, va, vmm_v2p(phys), PAGE_USER | PAGE_RW | PAGE_PRESENT);
            } else {
                /* p_memsz > p_filesz: .bss / zero tail — need present mappings (not demand-only). */
                void* zphys = kalloc();
                if (!zphys) {
                    pr_err("elf: out of memory allocating bss page for segment %d\n", i);
                    proc_free_pages(tracker);
                    return 0;
                }
                if (proc_tracker_add(tracker, zphys) < 0) {
                    pr_err("elf: tracker_add failed for bss segment %d\n", i);
                    free_page(zphys);
                    proc_free_pages(tracker);
                    return 0;
                }
                uint8_t* zp = (uint8_t*)zphys;
                for (int k = 0; k < (int)PAGE_SIZE; k++) zp[k] = 0;
                // `kalloc` returns a direct-map VA; the PTE takes the physical one.
                vmm_map(pd, va, vmm_v2p(zphys), PAGE_USER | PAGE_RW | PAGE_PRESENT);
            }
        }
    }

    return (void*)(uintptr_t)hdr.e_entry;
}

int elf_get_interp_path(const char* path, char* out, int out_max)
{
    if (!path || !out || out_max <= 0) return -1;

    vfs_node_t* file = vfs_walk_path_follow(vfs_root, (char*)path, 0);
    if (!file) return -1;

    Elf64_Ehdr hdr;
    if (read_vfs(file, 0, sizeof(Elf64_Ehdr), (char*)&hdr) <= 0) return -1;
    if (*(uint32_t*)hdr.e_ident != ELF_MAGIC) return -1;
    if (hdr.e_ident[EI_CLASS] != ELFCLASS64) return -1;
    if (hdr.e_ident[EI_DATA]  != ELFDATA2LSB) return -1;
    if (hdr.e_machine != EM_X86_64) return -1;
    if (hdr.e_phentsize < sizeof(Elf64_Phdr)) return -1;
    if ((uint32_t)hdr.e_phnum > 65535u) return -1;
    uint64_t ph_end_check = hdr.e_phoff +
                            (uint64_t)hdr.e_phnum * hdr.e_phentsize;
    if (ph_end_check > file->size) return -1;

    for (int i = 0; i < hdr.e_phnum; i++) {
        Elf64_Phdr ph;
        if (read_vfs(file, (uint32_t)(hdr.e_phoff + (uint64_t)i * hdr.e_phentsize),
                     sizeof(Elf64_Phdr), (char*)&ph) <= 0)
            break;
        if (ph.p_type != PT_INTERP) continue;
        if (ph.p_filesz == 0 || ph.p_filesz > (uint64_t)out_max) return -1;

        int n = read_vfs(file, (uint32_t)ph.p_offset, (uint32_t)ph.p_filesz, out);
        if (n <= 0) return -1;
        if (n >= out_max) n = out_max - 1;
        out[n] = '\0';
        return n;
    }
    return -1;
}

void* load_elf_interp(char* path, char* interp_path, uint64_t* pd,
                      proc_page_tracker_t* tracker, elf_interp_info_t* info)
{
    if (!path || !interp_path || !pd || !tracker || !info) return 0;
    memset(info, 0, sizeof(*info));

    vfs_node_t* main_file = vfs_walk_path_follow(vfs_root, path, 0);
    if (!main_file) {
        pr_warn("elf: main not found: %s\n", path);
        return 0;
    }
    vfs_node_t* interp_file = vfs_walk_path_follow(vfs_root, interp_path, 0);
    if (!interp_file) {
        pr_warn("elf: interpreter not found: %s\n", interp_path);
        return 0;
    }

    uint64_t m_entry = 0;
    uint32_t m_min = 0, m_phdr = 0, m_phnum = 0;
    if (_map_image(main_file, pd, tracker, &m_entry, &m_min, &m_phdr, &m_phnum) != 0) {
        pr_err("elf: failed to map main image: %s\n", path);
        proc_free_pages(tracker);
        return 0;
    }
    info->main_entry = (uint32_t)m_entry;
    info->main_base  = m_min;
    info->main_phdr  = m_phdr;
    info->main_phnum = m_phnum;

    uint64_t i_entry = 0;
    uint32_t i_min = 0, i_phdr = 0, i_phnum = 0;
    if (_map_image(interp_file, pd, tracker, &i_entry, &i_min, &i_phdr, &i_phnum) != 0) {
        pr_err("elf: failed to map interpreter: %s\n", interp_path);
        proc_free_pages(tracker);
        return 0;
    }
    info->interp_base = i_min;

    return (void*)(uintptr_t)i_entry;
}

uint32_t elf_get_brk_start(struct vfs_node* file) {
    if (!file) return 0;

    Elf64_Ehdr hdr;
    if (read_vfs(file, 0, sizeof(Elf64_Ehdr), (char*)&hdr) <= 0) return 0;
    if (*(uint32_t*)hdr.e_ident != ELF_MAGIC) return 0;
    if (hdr.e_phentsize < sizeof(Elf64_Phdr)) return 0;
    if ((uint32_t)hdr.e_phnum > 65535u) return 0;
    uint64_t ph_end_check = hdr.e_phoff + (uint64_t)hdr.e_phnum * hdr.e_phentsize;
    if (ph_end_check > file->size) return 0;

    uint64_t highest = 0;
    for (int i = 0; i < hdr.e_phnum; i++) {
        Elf64_Phdr ph;
        if (read_vfs(file,
                     (uint32_t)(hdr.e_phoff + (uint64_t)i * hdr.e_phentsize),
                     sizeof(Elf64_Phdr), (char*)&ph) <= 0)
            break;
        if (ph.p_type != PT_LOAD) continue;
        if (ph.p_vaddr + ph.p_memsz < ph.p_vaddr) continue;
        uint64_t end = ph.p_vaddr + ph.p_memsz;
        if (!_elf_seg_ok(ph.p_vaddr & ~0xFFFull, (end + 0xFFFull) & ~0xFFFull))
            continue;
        if (end > highest) highest = end;
    }

    return (uint32_t)((highest + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1));
}

#include "task.h"
#include "klib.h"

void elf_load_exec_symtab(const char* path, struct proc_metadata* proc) {
    if (!path || !proc) return;
    proc->exec_symtab = 0;
    proc->exec_strtab = 0;
    proc->exec_symtab_count = 0;

    vfs_node_t* base = (path[0] == '/') ? vfs_root : vfs_root;
    struct vfs_node* file = vfs_walk_path_follow(base, (char*)path, 0);
    if (!file) return;

    Elf64_Ehdr hdr;
    if (read_vfs(file, 0, sizeof(Elf64_Ehdr), (char*)&hdr) <= 0) return;
    if (*(uint32_t*)hdr.e_ident != ELF_MAGIC) return;
    if (hdr.e_ident[EI_CLASS] != ELFCLASS64) return;
    if (hdr.e_shentsize < sizeof(Elf64_Shdr)) return;
    if ((uint32_t)hdr.e_shnum > 256) return;
    uint64_t sh_end_check = hdr.e_shoff + (uint64_t)hdr.e_shnum * hdr.e_shentsize;
    if (sh_end_check > file->size) return;

    // Find the PT_LOAD segment with the lowest vaddr to determine base
    uint64_t load_base = 0xFFFFFFFFFFFFFFFFull;
    for (int i = 0; i < hdr.e_phnum && hdr.e_phentsize >= sizeof(Elf64_Phdr); i++) {
        Elf64_Phdr ph;
        if (read_vfs(file, (uint32_t)(hdr.e_phoff + (uint64_t)i * hdr.e_phentsize),
                     sizeof(Elf64_Phdr), (char*)&ph) <= 0) break;
        if (ph.p_type == PT_LOAD && ph.p_vaddr < load_base)
            load_base = ph.p_vaddr;
    }
    proc->exec_base = (load_base == 0xFFFFFFFFFFFFFFFFull) ? 0 : (uint32_t)load_base;

    // Read section headers
    Elf64_Shdr* shdrs = kmalloc(hdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs) return;
    if (read_vfs(file, (uint32_t)hdr.e_shoff, hdr.e_shnum * sizeof(Elf64_Shdr),
                 (char*)shdrs) <= 0) {
        kfree(shdrs);
        return;
    }

    // Read section header string table
    char* shstrtab = 0;
    if (hdr.e_shstrndx < hdr.e_shnum && shdrs[hdr.e_shstrndx].sh_size > 0) {
        shstrtab = kmalloc(shdrs[hdr.e_shstrndx].sh_size);
        if (shstrtab) {
            read_vfs(file, (uint32_t)shdrs[hdr.e_shstrndx].sh_offset,
                     (uint32_t)shdrs[hdr.e_shstrndx].sh_size, shstrtab);
        }
    }

    // Find SHT_SYMTAB and its linked SHT_STRTAB
    Elf64_Shdr* sym_sh = 0;
    Elf64_Shdr* str_sh = 0;
    for (int i = 0; i < hdr.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB && !sym_sh) sym_sh = &shdrs[i];
        if (shdrs[i].sh_type == SHT_STRTAB && shdrs[i].sh_entsize == 0) str_sh = &shdrs[i];
    }

    // Use the linked strtab from the symtab section
    if (sym_sh && sym_sh->sh_link < hdr.e_shnum)
        str_sh = &shdrs[sym_sh->sh_link];

    if (sym_sh && str_sh && sym_sh->sh_size > 0) {
        proc->exec_symtab = kmalloc((uint32_t)sym_sh->sh_size);
        proc->exec_strtab = kmalloc((uint32_t)str_sh->sh_size);
        if (proc->exec_symtab && proc->exec_strtab) {
            read_vfs(file, (uint32_t)sym_sh->sh_offset, (uint32_t)sym_sh->sh_size,
                     (char*)proc->exec_symtab);
            read_vfs(file, (uint32_t)str_sh->sh_offset, (uint32_t)str_sh->sh_size,
                     proc->exec_strtab);
            proc->exec_symtab_count = (uint32_t)(sym_sh->sh_size / sizeof(Elf64_Sym));
        } else {
            if (proc->exec_symtab) { kfree(proc->exec_symtab); proc->exec_symtab = 0; }
            if (proc->exec_strtab) { kfree(proc->exec_strtab); proc->exec_strtab = 0; }
        }
    }

    if (shstrtab) kfree(shstrtab);
    kfree(shdrs);
}
