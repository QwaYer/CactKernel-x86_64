/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "procfs.h"
#include "procfs_internal.h"
#include "ioctl_abi.h"
#include "vfs.h"
#include "kernel.h"
#include "memory.h"
#include "slab.h"
#include "shm.h"
#include "swap.h"
#include "zram.h"
#include "zswap.h"
#include "pagecache.h"
#include "page_fault.h"
#include "oom.h"
#include "irqstat.h"
#include "thermal.h"
#include "hypervisor.h"
#include "klib.h"
#include "task.h"
#include "version.h"
#include "initfs_modblob.h"
#include "cpudev.h"
#include "apic.h"
#include "msi.h"
#include "energy.h"
#include "rtc.h"
#include "tick.h"
#include "vfsdev.h"
#include "module/kmod.h"
#include "fs_mod.h"
#include "usb_mod.h"
#include "usb.h"
#include "dmi.h"
#include "pci_driver.h"

// Mutable host name reported by /proc/uname (default "cact").  Bounded to the
// kernel's 65-byte utsname field.
static char procfs_nodename[65] = "cact";

const char *procfs_get_nodename(void) { return procfs_nodename; }

void procfs_set_nodename(const char *name) {
    if (!name || !name[0]) return;
    int i = 0;
    for (; name[i] && i < 64; i++) procfs_nodename[i] = name[i];
    procfs_nodename[i] = '\0';
}

// Approximate CPU MHz via short TSC busy-wait.
static uint32_t _tsc_mhz(void) {
    uint32_t lo1, hi1, lo2, hi2;
    __asm__ volatile("rdtsc" : "=a"(lo1), "=d"(hi1));
    volatile uint32_t c = 10000000;
    while (c--) __asm__ volatile("nop");
    __asm__ volatile("rdtsc" : "=a"(lo2), "=d"(hi2));
    uint32_t delta = lo2 - lo1;
    return delta / 10000u;
}

// /proc/cpuinfo generator — uses cpudev.c cached data + the energy core map
int _cpuinfo_read(uint64_t off, uint32_t size, char *buf) {
    /* Sized for 16 logical CPUs including the feature line.  Both the generator
     * and the per-core loop are bounds-checked, so more cores truncate the file
     * instead of running past this frame (the previous 1.5 KB buffer with an
     * unbounded append smashed the kernel stack from ~6 CPUs up). */
    char tmp[4096];
    int  p = 0;

    #define _APP(s) { const char *_s=(s); while (*_s && p < (int)sizeof(tmp) - 1) tmp[p++]=*_s++; }
    #define _APPN(n) { char _nb[16]; snprintf(_nb, sizeof(_nb), "%d", (int)(n)); _APP(_nb); }

    uint32_t mhz = _tsc_mhz();
    uint32_t present = energy_core_count_present();
    if (present == 0) present = 1;

    for (uint32_t cpu = 0; cpu < present; cpu++) {
        /* Reserve room for one full core block (the cpu0 feature line is the
         * largest single append). */
        if (p > (int)sizeof(tmp) - 512)
            break;

        uint32_t apic_id = energy_core_lapic_id(cpu);
        if (apic_id == 0xFFFFFFFFu && cpu == 0)
            apic_id = apic_lapic_id();

        _APP("processor       : "); _APPN(cpu); _APP("\n");
        _APP("apicid          : "); _APPN(apic_id); _APP("\n");
        _APP("physical id     : "); _APPN(cpu_topo_package(cpu)); _APP("\n");
        _APP("siblings        : "); _APPN(cpu_topo_siblings(cpu)); _APP("\n");
        _APP("core id         : "); _APPN(cpu_topo_core(cpu)); _APP("\n");
        _APP("cpu cores       : "); _APPN(cpu_topo_cpu_cores(cpu)); _APP("\n");
        _APP("vendor_id       : "); _APP(cpu_vendor_str(cpu_vendor())); _APP("\n");
        _APP("model name      : "); _APP(cpu_brand_str()); _APP("\n");
        _APP("cpu MHz         : "); _APPN(mhz); _APP("\n");

        switch (energy_core_role(cpu)) {
        case ENERGY_ROLE_MASTER: _APP("role            : master\n"); break;
        case ENERGY_ROLE_WORKER: _APP("role            : worker\n"); break;
        default:                 _APP("role            : none\n");  break;
        }
        switch (energy_core_cstate(cpu)) {
        case ENERGY_CSTATE_C0: _APP("cstate          : C0\n"); break;
        case ENERGY_CSTATE_C1: _APP("cstate          : C1\n"); break;
        case ENERGY_CSTATE_C3: _APP("cstate          : C3\n"); break;
        case ENERGY_CSTATE_C6: _APP("cstate          : C6\n"); break;
        default:               _APP("cstate          : ?\n");  break;
        }
        _APP("online          : "); _APP(energy_core_is_online(cpu) ? "yes\n" : "no\n");
        _APP("idle            : "); _APP(energy_core_is_idle(cpu) ? "yes\n" : "no\n");
        _APP("ipi halted      : "); _APPN(energy_ipi_halt_sent(cpu)); _APP("/");
        _APPN(energy_ipi_halt_recv(cpu)); _APP(" (sent/recv)\n");
        _APP("ipi woken       : "); _APPN(energy_ipi_wake_sent(cpu)); _APP("/");
        _APPN(energy_ipi_wake_recv(cpu)); _APP(" (sent/recv)\n");

        // Full feature flags are identical on every core; print once (cpu0).
        if (cpu != 0)
            continue;

        _APP("flags           :");
        uint32_t edx = cpu_features_edx();
        uint32_t ecx = cpu_features_ecx();
        uint32_t ext_edx = cpu_features_ext_edx();
        uint32_t l7_ebx = cpu_features_leaf7_ebx();
        uint32_t l7_ecx = cpu_features_leaf7_ecx();
        uint32_t l7_edx = cpu_features_leaf7_edx();

        if (edx & (1u<<0))  _APP(" fpu");
        if (edx & (1u<<1))  _APP(" vme");
        if (edx & (1u<<2))  _APP(" de");
        if (edx & (1u<<3))  _APP(" pse");
        if (edx & (1u<<4))  _APP(" tsc");
        if (edx & (1u<<5))  _APP(" msr");
        if (edx & (1u<<6))  _APP(" pae");
        if (edx & (1u<<7))  _APP(" mce");
        if (edx & (1u<<8))  _APP(" cx8");
        if (edx & (1u<<9))  _APP(" apic");
        if (edx & (1u<<11)) _APP(" sep");
        if (edx & (1u<<12)) _APP(" mtrr");
        if (edx & (1u<<13)) _APP(" pge");
        if (edx & (1u<<14)) _APP(" mca");
        if (edx & (1u<<15)) _APP(" cmov");
        if (edx & (1u<<16)) _APP(" pat");
        if (edx & (1u<<17)) _APP(" pse36");
        if (edx & (1u<<19)) _APP(" clflush");
        if (edx & (1u<<21)) _APP(" ds");
        if (edx & (1u<<22)) _APP(" acpi");
        if (edx & (1u<<23)) _APP(" mmx");
        if (edx & (1u<<24)) _APP(" fxsr");
        if (edx & (1u<<25)) _APP(" sse");
        if (edx & (1u<<26)) _APP(" sse2");
        if (edx & (1u<<28)) _APP(" ht");
        if (edx & (1u<<29)) _APP(" tm1");
        if (edx & (1u<<31)) _APP(" pbe");

        if (ecx & (1u<<0))  _APP(" sse3");
        if (ecx & (1u<<1))  _APP(" pclmulqdq");
        if (ecx & (1u<<2))  _APP(" dtes64");
        if (ecx & (1u<<3))  _APP(" monitor");
        if (ecx & (1u<<4))  _APP(" dscpl");
        if (ecx & (1u<<5))  _APP(" vmx");
        if (ecx & (1u<<6))  _APP(" smx");
        if (ecx & (1u<<7))  _APP(" est");
        if (ecx & (1u<<8))  _APP(" tm2");
        if (ecx & (1u<<9))  _APP(" ssse3");
        if (ecx & (1u<<12)) _APP(" fma");
        if (ecx & (1u<<13)) _APP(" cx16");
        if (ecx & (1u<<14)) _APP(" xtpr");
        if (ecx & (1u<<15)) _APP(" pdcm");
        if (ecx & (1u<<17)) _APP(" pcid");
        if (ecx & (1u<<19)) _APP(" sse4_1");
        if (ecx & (1u<<20)) _APP(" sse4_2");
        if (ecx & (1u<<21)) _APP(" x2apic");
        if (ecx & (1u<<22)) _APP(" movbe");
        if (ecx & (1u<<23)) _APP(" popcnt");
        if (ecx & (1u<<24)) _APP(" tsc-deadline");
        if (ecx & (1u<<25)) _APP(" aes");
        if (ecx & (1u<<26)) _APP(" xsave");
        if (ecx & (1u<<27)) _APP(" osxsave");
        if (ecx & (1u<<28)) _APP(" avx");
        if (ecx & (1u<<29)) _APP(" f16c");
        if (ecx & (1u<<30)) _APP(" rdrand");
        if (ecx & (1u<<31)) _APP(" hypervisor");

        if (l7_ebx & (1u<<0))  _APP(" fsgsbase");
        if (l7_ebx & (1u<<1))  _APP(" tsc-adjust");
        if (l7_ebx & (1u<<2))  _APP(" sgx");
        if (l7_ebx & (1u<<3))  _APP(" bmi1");
        if (l7_ebx & (1u<<4))  _APP(" hle");
        if (l7_ebx & (1u<<5))  _APP(" avx2");
        if (l7_ebx & (1u<<7))  _APP(" smep");
        if (l7_ebx & (1u<<8))  _APP(" bmi2");
        if (l7_ebx & (1u<<9))  _APP(" erms");
        if (l7_ebx & (1u<<10)) _APP(" invpcid");
        if (l7_ebx & (1u<<11)) _APP(" rtm");
        if (l7_ebx & (1u<<14)) _APP(" mpx");
        if (l7_ebx & (1u<<18)) _APP(" rdseed");
        if (l7_ebx & (1u<<19)) _APP(" adx");
        if (l7_ebx & (1u<<20)) _APP(" smap");
        if (l7_ebx & (1u<<23)) _APP(" clflushopt");
        if (l7_ebx & (1u<<24)) _APP(" clwb");
        if (l7_ebx & (1u<<29)) _APP(" sha");

        if (l7_ecx & (1u<<2))  _APP(" umip");
        if (l7_ecx & (1u<<3))  _APP(" pku");
        if (l7_ecx & (1u<<4))  _APP(" ospke");
        if (l7_ecx & (1u<<7))  _APP(" cet-ss");
        if (l7_ecx & (1u<<9))  _APP(" vaes");
        if (l7_ecx & (1u<<10)) _APP(" vpclmulqdq");
        if (l7_ecx & (1u<<16)) _APP(" la57");

        if (l7_edx & (1u<<10)) _APP(" md-clear");
        if (l7_edx & (1u<<26)) _APP(" ibrs");
        if (l7_edx & (1u<<27)) _APP(" stibp");
        if (l7_edx & (1u<<28)) _APP(" l1d-flush");
        if (l7_edx & (1u<<29)) _APP(" arch-cap");
        if (l7_edx & (1u<<30)) _APP(" core-cap");
        if (l7_edx & (1u<<31)) _APP(" ssbd");

        if (ext_edx & (1u<<11)) _APP(" syscall");
        if (ext_edx & (1u<<20)) _APP(" nx");
        if (ext_edx & (1u<<22)) _APP(" mmxext");
        if (ext_edx & (1u<<25)) _APP(" fxsr-opt");
        if (ext_edx & (1u<<26)) _APP(" pdpe1gb");
        if (ext_edx & (1u<<27)) _APP(" rdtscp");
        if (ext_edx & (1u<<29)) _APP(" lm");
        _APP("\n");
    }

    #undef _APP
    #undef _APPN

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// Memory total (set by mntfs during init)
static uint32_t _mb_mem_total_kb = 0;

void procfs_set_meminfo(uint32_t mem_total_kb) {
    _mb_mem_total_kb = mem_total_kb;
}

static uint32_t _get_total_memory_kb(void) {
    return _mb_mem_total_kb;
}

// /proc/apic generator
int _apic_read(uint64_t off, uint32_t size, char *buf) {
    char tmp[512]; int p = 0;

    #define _A(s) { const char *_s=(s); while(*_s) tmp[p++]=*_s++; }
    #define _N(n) { char _b[16]; snprintf(_b, sizeof(_b), "%d", (int)(n)); _A(_b); }

    _A("APIC enabled    : ");
    _A(apic_is_enabled() ? "yes" : "no"); _A("\n");

    if (apic_is_enabled()) {
        _A("LAPIC mode      : ");
        _A(apic_x2apic_mode() ? "x2APIC (MSR)" : "xAPIC (MMIO)");
        _A("\n");
        _A("LAPIC reason    : "); _A(apic_x2apic_note()); _A("\n");
        _A("LAPIC base      : 0x");
        { char h[12]; snprintf(h, sizeof(h), "0x%x", (unsigned)apic_lapic_base()); _A(h); }
        _A("\n");
        _A("LAPIC ID        : "); _N(apic_lapic_id()); _A("\n");

        uint32_t io_base, io_id, io_max, io_gsi;
        if (apic_ioapic_info(&io_base, &io_id, &io_max, &io_gsi)) {
            _A("IOAPIC ID       : "); _N(io_id); _A("\n");
            _A("IOAPIC base     : 0x");
            { char h[12]; snprintf(h, sizeof(h), "0x%x", (unsigned)io_base); _A(h); }
            _A("\n");
            _A("IOAPIC max entry: "); _N(io_max); _A("\n");
            _A("IOAPIC GSI base : "); _N(io_gsi); _A("\n");

            _A("ISA IRQ overrides:");
            for (int i = 0; i < 16; i++) {
                int gsi = apic_irq_override(i);
                if (gsi != i) {
                    _A(" "); _N(i); _A("->"); _N(gsi);
                }
            }
            _A("\n");
        }
    }

    _A("irq vectors     : 0x");
    { char h[12]; snprintf(h, sizeof(h), "0x%x", (unsigned)MSIDEV_VECTOR_BASE); _A(h); }
    _A("-0x");
    { char h[12]; snprintf(h, sizeof(h), "0x%x", (unsigned)(MSIDEV_VECTOR_END - 1)); _A(h); }
    _A(" ("); _N(MSIDEV_VECTOR_COUNT); _A(" total)\n");

    int used = msidev_used_vectors();
    _A("irq vectors used: "); _N(used); _A("\n");
    _A("irq vectors free: "); _N(MSIDEV_VECTOR_COUNT - used); _A("\n");

    #undef _A
    #undef _N

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// Bytes of kernel stacks held by live tasks, in kB.  Every task and thread
// owns one KERNEL_STACK_SIZE stack, allocated from the kernel heap when the
// task is created — so this is a heap figure, not a PMM one, and `free` does
// not fold it into its `used` calculation.
static uint32_t _kernel_stack_kb(void) {
    uint32_t tasks = 0;
    irq_spinlock_acquire(&scheduler_lock);
    for (struct task_struct *t = task_list_head; t; t = t->next)
        tasks++;
    irq_spinlock_release(&scheduler_lock);
    return (uint32_t)((uint64_t)tasks * KERNEL_STACK_SIZE / 1024u);
}

// /proc/meminfo generator
//
// Physical accounting comes from the PMM (frames), not from the fixed kernel
// heap window: MemTotal is the usable RAM the boot map handed to the PMM minus
// the hard-reserved low region (RESERVED_END — kernel image, static page tables
// and the low user VA region), MemFree is the PMM free list plus the unused part
// of the kernel heap window, and MemUsed is the remainder.  The kernel heap /
// slab / shm / page-cache figures are reported separately so `free` can show
// them without disturbing the physical numbers.
int _meminfo_read(uint64_t off, uint32_t size, char *buf) {
    char tmp[1280]; int p = 0;

    const uint32_t frame_kb    = PAGE_SIZE / 1024u;      /* 4 KiB per frame      */
    const uint32_t reserved_kb = RESERVED_END / 1024u;   /* low-memory reserve */

    uint32_t pmm_total_kb = pmm_total_frames() * frame_kb;
    uint32_t pmm_free_kb  = pmm_free_frames()  * frame_kb;

    /* Fall back to the multiboot total if the PMM was not probed. */
    if (pmm_total_kb == 0) pmm_total_kb = _get_total_memory_kb();

    uint32_t mem_total_kb = pmm_total_kb > reserved_kb ? pmm_total_kb - reserved_kb
                                                       : pmm_total_kb;

    heap_stats_t heap_stats = heap_get_stats();
    /* HeapTotal is the payload across every heap region (the boot window plus any
     * the allocator grew), so it tracks HeapRegions rather than the fixed
     * HEAP_SIZE.  HeapUsed is the in-use share of it. */
    uint32_t heap_total_kb = (heap_stats.free_bytes + heap_stats.used_bytes) / 1024u;
    uint32_t heap_free_kb  = heap_stats.free_bytes / 1024u;
    uint32_t heap_used_kb  = heap_stats.used_bytes / 1024u;
    uint32_t heap_largest_kb = heap_stats.largest_free / 1024u;

    uint32_t mem_free_kb = pmm_free_kb + heap_free_kb;
    if (mem_free_kb > mem_total_kb) mem_free_kb = mem_total_kb;
    uint32_t mem_used_kb  = mem_total_kb - mem_free_kb;
    uint32_t mem_avail_kb = mem_free_kb;

    uint32_t slab_kb  = slab_total_bytes() / 1024u;
    uint32_t shmem_kb = shm_total_bytes()  / 1024u;

    /* CactOS has a single block/page cache, not Linux's split of a raw block
     * buffer cache and a file page cache: pc_get_page() caches block-device
     * blocks for every consumer, filesystems included.  It is therefore
     * reported as Cached and Buffers stays 0 — the same "buff/cache" column in
     * `free`, but named for the cache it actually is. */
    pc_stats_t pc        = pc_get_stats();
    uint32_t   cached_kb = pc.cached_bytes / 1024u;
    uint32_t   dirty_kb  = pc.dirty_bytes  / 1024u;

    swap_stats_t sw = swap_get_stats();
    uint32_t swap_total_kb = sw.total_slots * frame_kb;
    uint32_t swap_used_kb  = sw.used_slots  * frame_kb;
    uint32_t swap_free_kb  = swap_total_kb > swap_used_kb ? swap_total_kb - swap_used_kb : 0;

    uint32_t kernel_stack_kb = _kernel_stack_kb();

    /* Resident user pages and page tables: walk each distinct address space
     * once (threads share a page map), then add the kernel's own tables and the
     * hypervisor's.  The walk is held under scheduler_lock so a task cannot be
     * freed underneath it. */
    uint32_t anon_pages = 0, mapped_pages = 0, ptable_pages = 0;
    irq_spinlock_acquire(&scheduler_lock);
    for (struct task_struct *t = task_list_head; t; t = t->next) {
        if (!t->page_directory) continue;
        int dup = 0;
        for (struct task_struct *u = task_list_head; u && u != t; u = u->next)
            if (u->page_directory == t->page_directory) { dup = 1; break; }
        if (dup) continue;
        vmm_user_stats_t us = vmm_user_stats(t->page_directory, t->proc);
        anon_pages   += us.anon_pages;
        mapped_pages += us.file_pages;
        ptable_pages += us.ptable_pages;
    }
    irq_spinlock_release(&scheduler_lock);
    uint32_t hv_tables = hv_ptable_pages();
    ptable_pages += vmm_kernel_ptable_pages() + hv_tables;

    /* CactOS-specific figures: the boot reservation the PMM hard-reserves, the
     * RAM it manages, the fixed page-cache pool, and the hypervisor's live
     * translation tables and guest RAM.  None of these map onto a Linux meminfo
     * field. */
    uint32_t mem_reserved_kb  = pmm_reserved_end() / 1024u;
    uint32_t pmm_managed_kb   = pmm_total_kb;
    uint32_t hv_table_kb      = hv_tables * frame_kb;
    uint32_t guest_mem_kb     = hv_guest_memory_pages() * frame_kb;

    #define _A(s) { const char *_s=(s); while(*_s) tmp[p++]=*_s++; }
    #define _N(n) { char _b[16]; snprintf(_b, sizeof(_b), "%d", (int)(n)); _A(_b); }

    _A("MemTotal:        "); _N(mem_total_kb); _A(" kB\n");
    _A("MemFree:         "); _N(mem_free_kb);  _A(" kB\n");
    _A("MemAvailable:    "); _N(mem_avail_kb); _A(" kB\n");
    _A("MemUsed:         "); _N(mem_used_kb);  _A(" kB\n");
    _A("Buffers:         0 kB\n");
    _A("Cached:          "); _N(cached_kb);    _A(" kB\n");
    _A("SwapCached:      0 kB\n");
    _A("Dirty:           "); _N(dirty_kb);     _A(" kB\n");
    _A("Writeback:       0 kB\n");
    _A("AnonPages:       "); _N(anon_pages   * frame_kb); _A(" kB\n");
    _A("Mapped:          "); _N(mapped_pages * frame_kb); _A(" kB\n");
    _A("Slab:            "); _N(slab_kb);      _A(" kB\n");
    _A("Shmem:           "); _N(shmem_kb);     _A(" kB\n");
    _A("KernelStack:     "); _N(kernel_stack_kb); _A(" kB\n");
    _A("PageTables:      "); _N(ptable_pages * frame_kb); _A(" kB\n");
    _A("SwapTotal:       "); _N(swap_total_kb); _A(" kB\n");
    _A("SwapFree:        "); _N(swap_free_kb);  _A(" kB\n");
    _A("SwapUsed:        "); _N(swap_used_kb);  _A(" kB\n");
    _A("HeapTotal:       "); _N(heap_total_kb); _A(" kB\n");
    _A("HeapFree:        "); _N(heap_free_kb);  _A(" kB\n");
    _A("HeapUsed:        "); _N(heap_used_kb);  _A(" kB\n");
    _A("HeapLargest:     "); _N(heap_largest_kb); _A(" kB\n");
    _A("HeapBlocks:      "); _N(heap_stats.free_blocks); _A("/"); _N(heap_stats.total_blocks); _A("\n");
    _A("HeapRegions:     "); _N(heap_stats.regions); _A("\n");
    _A("MemReserved:     "); _N(mem_reserved_kb); _A(" kB\n");
    _A("PmmManaged:      "); _N(pmm_managed_kb);  _A(" kB\n");
    _A("PageCachePool:   "); _N(pc.pool_pages);    _A(" pages\n");
    _A("HypervisorTables:"); _A(" "); _N(hv_table_kb); _A(" kB\n");
    _A("GuestMemory:     "); _N(guest_mem_kb);  _A(" kB\n");

    #undef _A
    #undef _N

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

//
// /proc/zmem — the read side of the compressed-memory interface: the zswap
// pool plus every zram device, with original/compressed sizes so the
// compression the hardware pays for is visible (what `zmemctl` reports and
// `free`-style tools can read).  Written by /dev/zmem's ioctls and by the
// zram=/zswap= command line; see Cact/kernel/memory/{zram,zswap}.h.
int _zmem_read(uint64_t off, uint32_t size, char *buf) {
    char tmp[1024]; int p = 0;

    /* Bounded appends: _meminfo_read's _A has no capacity guard, so this
     * generator uses the guarded form to stay safe if the device count grows. */
    #define _A(s) { const char *_s=(s); while (*_s && p < (int)sizeof(tmp) - 1) tmp[p++]=*_s++; }
    #define _N(n) { char _b[16]; snprintf(_b, sizeof(_b), "%d", (int)(n)); _A(_b); }
    #define _KB(n) { char _b[24]; snprintf(_b, sizeof(_b), "%llu", (unsigned long long)((n) / 1024u)); _A(_b); }
    /* Percentage of the original that the compressed form saves. */
    #define _SAVED(orig, comp) ((unsigned)(((orig) > (comp)) ? (((orig) - (comp)) * 100ull / (orig)) : 0ull))

    zswap_stats_t zs;
    memset(&zs, 0, sizeof(zs));
    zswap_get_stats(&zs);
    _A("zswap: "); _A(zs.enabled ? "on" : "off");
    _A(" writeback="); _N(zs.writeback);
    _A(" level="); _N(zs.level);
    _A("\n  budget:  "); _N(zs.capacity_pages); _A(" pages, ");
    _KB(zs.budget_bytes); _A(" kB\n");
    _A("  pooled:  "); _N(zs.pool_pages); _A(" pages, ");
    _KB(zs.stored_bytes); _A(" kB from "); _KB(zs.original_bytes);
    _A(" kB (saves "); _N(_SAVED(zs.original_bytes, zs.stored_bytes)); _A("%)\n");
    _A("  events:  "); _N(zs.stores); _A(" stores, ");
    _N(zs.store_fail); _A(" refused, "); _N(zs.loads); _A(" loads, ");
    _N(zs.writebacks); _A(" writebacks\n");

    int n = zram_count();
    for (int i = 0; i < n; i++) {
        zram_info_t zi;
        if (zram_get_info(i, &zi) != 0) continue;
        _A("zram "); _A(zi.name);
        _A(": "); _N(zi.capacity_pages); _A(" pages capacity\n");
        _A("  stored:  "); _N(zi.stored_pages); _A(" pages, ");
        _KB(zi.stored_bytes); _A(" kB from "); _KB(zi.original_bytes);
        _A(" kB (saves "); _N(_SAVED(zi.original_bytes, zi.stored_bytes)); _A("%)\n");
        _A("  io:      "); _N(zi.pages_in); _A(" reads, ");
        _N(zi.pages_out); _A(" writes\n");
    }

    #undef _A
    #undef _N
    #undef _KB
    #undef _SAVED

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

extern unsigned int timer_ticks_get(void);
extern uint64_t     sched_ctxt_count(void);
extern uint32_t     sched_next_pid(void);

// /proc/uname — binary struct cact_uname_t (relay for uname()).
int _uname_read(uint64_t off, uint32_t size, char *buf) {
    cact_uname_t u;
    memset(&u, 0, sizeof(u));
    const char *sysname  = "CactOS";
    const char *nodename = procfs_get_nodename();
    const char *release  = kernel_version;
    const char *machine  = "x86_64";
    char version[65];
    snprintf(version, sizeof(version), "#1 %s", kernel_build_time);

    int i;
    for (i = 0; sysname[i] && i < 64; i++)  u.sysname[i]  = sysname[i];
    for (i = 0; nodename[i] && i < 64; i++) u.nodename[i] = nodename[i];
    for (i = 0; release[i] && i < 64; i++)  u.release[i]  = release[i];
    for (i = 0; version[i] && i < 64; i++)  u.version[i]  = version[i];
    for (i = 0; machine[i] && i < 64; i++)  u.machine[i]  = machine[i];

    uint32_t len = sizeof(u);
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, (const char *)&u + off, size);
    return (int)size;
}

// /proc/dmi — SMBIOS system identity (vendor / product / BIOS version) as
// "key: value" lines.  Zero-length when the firmware exposes no SMBIOS, so a
// reader simply sees an empty file.
int _dmi_read(uint64_t off, uint32_t size, char *buf) {
    char tmp[256];
    int p = 0;
    const char *vendor  = dmi_vendor_string();
    const char *product = dmi_product_string();
    const char *bios    = dmi_bios_string();

    if (vendor)  p += snprintf(tmp + p, (int)sizeof(tmp) - p, "vendor: %s\n", vendor);
    if (product) p += snprintf(tmp + p, (int)sizeof(tmp) - p, "product: %s\n", product);
    if (bios)    p += snprintf(tmp + p, (int)sizeof(tmp) - p, "bios: %s\n", bios);

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// /proc/time — binary monotonic time (cact_time_t), used by the libc
// gettimeofday()/clock_gettime() relay instead of a dedicated syscall.
int _time_read(uint64_t off, uint32_t size, char *buf) {
    cact_time_t t;
    uint32_t ticks = timer_ticks_get();
    t.sec  = ticks / 100;
    t.usec = (ticks % 100) * (1000000 / 100);
    uint32_t len = sizeof(t);
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, (const char *)&t + off, size);
    return (int)size;
}

// /proc/wallclock — binary cact_time_t: civil time, i.e. seconds since the
// Unix epoch, from the CMOS RTC read at boot.  /proc/time stays the monotonic
// boot clock; this is the one to use when the answer has to agree with the
// outside world (X.509 validity, file timestamps).
int _wallclock_read(uint64_t off, uint32_t size, char *buf) {
    cact_time_t t;
    uint64_t us = rtc_epoch_usec();
    if (us == 0) {
        /* No usable RTC date: report the boot clock rather than 1970, so a
         * caller that only needs something monotonic still behaves. */
        uint32_t ticks = timer_ticks_get();
        t.sec  = ticks / 100;
        t.usec = (ticks % 100) * (1000000 / 100);
    } else {
        t.sec  = us / 1000000ull;
        t.usec = (uint32_t)(us % 1000000ull);
    }
    uint32_t len = sizeof(t);
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, (const char *)&t + off, size);
    return (int)size;
}

// /proc/uptime generator
int _uptime_read(uint64_t off, uint32_t size, char *buf) {
    char tmp[64];
    int  p = 0;
    char nb[16]; snprintf(nb, sizeof(nb), "%d", (int)(timer_ticks_get() / 100));
    for (int i = 0; nb[i]; i++) tmp[p++] = nb[i];
    const char *s = " seconds\n";
    for (int i = 0; s[i]; i++) tmp[p++] = s[i];
    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// /proc/version generator
int _version_read(uint64_t off, uint32_t size, char *buf) {
    char tmp[512];
    int  p = 0;

    #define _V(s) { const char *_s=(s); while(*_s) tmp[p++]=*_s++; }

    _V("Cact Kernel ");  _V(kernel_version_meta);    _V("\n");
    _V("Arch: x86_64\n");
    _V("Compiler: ");    _V(kernel_compiler);   _V("\n");
    _V("Built by: ");    _V(kernel_builder);    _V("\n");
    _V("Commit: ");     _V(kernel_commit_hash); _V("\n");
    _V("Build: ");      _V(kernel_build_time);  _V("\n");

    #undef _V

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// /proc/mounts generator — the kernel layout mounts (from the VFS mount tree)
// followed by the block-device mounts tracked by vfsdev, all in the Linux
// mount-table form "<src> <path> <fstype> rw 0 0".
int _mounts_read(uint64_t off, uint32_t size, char *buf) {
    static char tmp[4096];
    int p = vfs_render_mounts(tmp, (int)sizeof(tmp) - 1);
    if (p < 0) p = 0;
    if (p < (int)sizeof(tmp) - 1) {
        int q = vfsdev_mounts_text(tmp + p, (int)sizeof(tmp) - p);
        if (q > 0) p += q;
    }
    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// /proc/modules generator — resident loadable modules in the Linux form
// "<name> <size> <refcount> - Live 0x00000000": filesystem modules (fs_mod),
// USB driver modules (usb_mod) and resident PCI kernel modules (kmod).  Size
// is the resident relocation image in bytes; the refcount is how many users
// the loader can account for — fs_mod: devices mounted; usb_mod: devices its
// drivers claim; kmod: PCI functions its driver serves.  Slots are scanned
// directly, not by count: unloading the first of two modules leaves a hole at
// slot 0.
int _modules_read(uint64_t off, uint32_t size, char *buf) {
    static char tmp[4096];
    int p = 0;
    int cap = (int)sizeof(tmp);

    for (int i = 0; i < FS_MOD_MAX && p <= cap - 128; i++) {
        const char *nm = fs_mod_instance(i);
        if (!nm) continue;
        p += snprintf(tmp + p, (size_t)(cap - p), "%s %u %d - Live 0x00000000\n",
                      nm, (unsigned)fs_mod_size(i), fs_mod_refs(i));
    }
    for (int i = 0; i < USB_MOD_MAX && p <= cap - 128; i++) {
        const char *nm = usb_mod_instance(i);
        if (!nm) continue;
        p += snprintf(tmp + p, (size_t)(cap - p), "%s %u %d - Live 0x00000000\n",
                      nm, (unsigned)usb_mod_size(i), usb_mod_refs(i));
    }
    for (int i = 0; i < KMOD_MAX_SLOTS && p <= cap - 128; i++) {
        const char *nm = kmod_name_at(i);
        if (!nm) continue;
        p += snprintf(tmp + p, (size_t)(cap - p), "%s %u %d - Live 0x00000000\n",
                      nm, (unsigned)kmod_size_at(i), kmod_refs_at(i));
    }
    if (p < 0) p = 0;

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// /proc/usb generator — one line per attached USB device:
//   <address> <vendor> <product> <class> <subclass> <protocol> <speed> <port>
// (vendor/product as 0x%04x, the rest decimal).  lsusb formats it.
int _usb_read(uint64_t off, uint32_t size, char *buf) {
    static char tmp[2048];
    int p = 0;
    int cap = (int)sizeof(tmp);

    int n = usb_device_count();
    for (int i = 0; i < n && p < cap - 96; i++) {
        const usb_device_t *d = usb_device_at(i);
        if (!d) continue;
        p += snprintf(tmp + p, (size_t)(cap - p),
                      "%u %04x %04x %02x %02x %02x %u %u\n",
                      (unsigned)d->address,
                      (unsigned)d->dev_desc.idVendor,
                      (unsigned)d->dev_desc.idProduct,
                      (unsigned)d->class_code,
                      (unsigned)d->subclass,
                      (unsigned)d->protocol,
                      (unsigned)d->speed,
                      (unsigned)d->port);
    }
    if (p < 0) p = 0;

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// /proc/pci generator — PCI overview: the pci_register_driver() structs (A) and
// every function found by pci_enumerate() (B).  lspci formats section B; the
// modunload [pci N] index and lsmod's driver fallback use section A.
int _pci_read(uint64_t off, uint32_t size, char *buf) {
    return pci_proc_read(off, size, buf);
}

// /proc/vmstat generator — the kernel's virtual-memory event counters, one
// "<name> <value>" per line.  Everything here is a cumulative counter or a
// current frame count, composed from the PMM, slab, shmem, page-cache, swap,
// page-fault and OOM getters (there is no central vm_stat array).  Names follow
// Linux where the meaning matches; CactOS-only figures keep a `_kb` suffix so
// they are not mistaken for Linux's page counts.
int _vmstat_read(uint64_t off, uint32_t size, char *buf) {
    static char tmp[1024];
    int p = 0;
    int cap = (int)sizeof(tmp);

    pf_stats_t   pf  = pf_get_stats();
    swap_stats_t sw  = swap_get_stats();
    pc_stats_t   pc  = pc_get_stats();
    oom_stats_t  oom = oom_get_stats();

    #define _V(name, val) do { \
        if (p <= cap - 64) \
            p += snprintf(tmp + p, (size_t)(cap - p), "%s %u\n", \
                          (name), (unsigned)(val)); \
    } while (0)

    _V("nr_free_pages", pmm_free_frames());
    _V("nr_slab_kb",    slab_total_bytes() / 1024u);
    _V("nr_shmem_kb",   shm_total_bytes()  / 1024u);
    _V("nr_cached_kb",  pc.cached_bytes    / 1024u);
    _V("nr_dirty_kb",   pc.dirty_bytes     / 1024u);

    _V("pgfault",       pf.total_faults);
    _V("pgmajfault",    pf.swap_ins);
    _V("pgdemand",      pf.demand_allocs);
    _V("pgcow",         pf.cow_copies);
    _V("pgstackgrow",   pf.stack_grows);
    _V("pgzero",        pf.zero_pages);
    _V("pgprotfault",   pf.protection_faults);
    _V("pgbadaccess",   pf.invalid_access);

    _V("pswpin",        sw.pages_swapped_in);
    _V("pswpout",       sw.pages_swapped_out);
    _V("swapfail",      sw.swap_failures);
    _V("swap_used_kb",  sw.used_slots * (PAGE_SIZE / 1024u));

    _V("oom_kill",      oom.oom_kills);

    #undef _V

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// /proc/interrupts generator — one row per vector that has a label or a
// non-zero count, with a per-CPU column and the vector's label.  The vector
// number is decimal (CactOS keys its IDT by vector, not by a Linux IRQ): the
// ISA IRQs are 0x21-0x2F, PCI INTx 0xF0-0xF7, the LAPIC timer 0xFE, the
// C-state IPIs 0xF8/0xF9, the spurious vector 0xFF, and MSI/MSI-X vectors
// 0x30-0xEF labelled with the PCI function that owns them.
int _interrupts_read(uint64_t off, uint32_t size, char *buf) {
    static char tmp[4096];
    int p = 0;
    int cap = (int)sizeof(tmp);

    int ncpu = energy_core_count_online();
    if (ncpu < 1) ncpu = 1;
    if (ncpu > 8) ncpu = 8;   /* keep one row inside the buffer */

    #define _IRQ(...) do { \
        if (p <= cap - 128) \
            p += snprintf(tmp + p, (size_t)(cap - p), __VA_ARGS__); \
    } while (0)

    _IRQ("%-11s", "");
    for (int c = 0; c < ncpu; c++) {
        char h[12];
        snprintf(h, sizeof(h), "CPU%d", c);
        _IRQ("%11s", h);
    }
    _IRQ("\n");

    for (unsigned int v = 0; v < IRQSTAT_VECTORS; v++) {
        const char *nm = irqstat_name_of(v);
        uint32_t tot = irqstat_vector_total(v);
        if (tot == 0 && (!nm || !nm[0])) continue;

        _IRQ("%3u: ", v);
        for (int c = 0; c < ncpu; c++) _IRQ("%11u", (unsigned)irqstat_cpu(c, v));
        if (nm && nm[0]) _IRQ("  %s", nm);
        _IRQ("\n");
    }

    #undef _IRQ

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// /proc/stat generator — the classic Linux shape: per-CPU tick totals, then the
// system counts.  Only user/system/idle are tracked (there is no nice/iowait/
// softirq/steal accounting), so those columns are 0.
int _stat_read(uint64_t off, uint32_t size, char *buf) {
    static char tmp[4096];
    int p = 0;
    int cap = (int)sizeof(tmp);

    int ncpu = energy_core_count_online();
    if (ncpu < 1) ncpu = 1;
    if (ncpu > tick_cpu_count()) ncpu = tick_cpu_count();
    if (ncpu > 16) ncpu = 16;

    #define _ST(...) do { \
        if (p <= cap - 128) \
            p += snprintf(tmp + p, (size_t)(cap - p), __VA_ARGS__); \
    } while (0)

    /* user nice system idle iowait irq softirq steal guest guest_nice */
    uint64_t au = 0, as = 0, ai = 0;
    for (int c = 0; c < ncpu; c++) {
        au += tick_cpu_user(c);
        as += tick_cpu_system(c);
        ai += tick_cpu_idle(c);
    }
    _ST("cpu  %llu 0 %llu %llu 0 0 0 0 0 0\n",
        (unsigned long long)au, (unsigned long long)as, (unsigned long long)ai);
    for (int c = 0; c < ncpu; c++)
        _ST("cpu%d %llu 0 %llu %llu 0 0 0 0 0 0\n", c,
            (unsigned long long)tick_cpu_user(c),
            (unsigned long long)tick_cpu_system(c),
            (unsigned long long)tick_cpu_idle(c));

    _ST("intr %llu\n", (unsigned long long)irqstat_total());
    _ST("ctxt %llu\n", (unsigned long long)sched_ctxt_count());

    /* btime is the wall-clock instant of boot: now minus uptime, when the RTC
     * handed us a date; 0 otherwise. */
    uint64_t now = rtc_epoch_sec();
    uint32_t up  = timer_ticks_get() / 100u;
    _ST("btime %llu\n", (now > up) ? (unsigned long long)(now - up) : 0ull);

    _ST("processes %u\n", (unsigned)(sched_next_pid() - 1u));

    /* procs_running counts Ready/Running tasks, procs_blocked the parked ones;
     * the per-CPU idle contexts (pid 0) are not counted, like Linux. */
    uint32_t running = 0, blocked = 0;
    irq_spinlock_acquire(&scheduler_lock);
    for (struct task_struct *t = task_list_head; t; t = t->next) {
        if (t->pid == 0) continue;
        switch (t->state) {
        case TASK_RUNNING:
        case TASK_READY:   running++; break;
        case TASK_SLEEPING:
        case TASK_WAITING: blocked++; break;
        default: break;
        }
    }
    irq_spinlock_release(&scheduler_lock);
    _ST("procs_running %u\n", (unsigned)running);
    _ST("procs_blocked %u\n", (unsigned)blocked);

    #undef _ST

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// /proc/sensors generator — a "<name> <temp_C>" table: one row per ACPI thermal
// zone (its _TMP, read live) plus the Intel DTS for the reading CPU.  Machines
// with neither see a single "no sensors available" line.
int _sensors_read(uint64_t off, uint32_t size, char *buf) {
    static char tmp[1024];
    int p = 0;
    int cap = (int)sizeof(tmp);
    int found = 0;

    #define _SN(...) do { \
        if (p <= cap - 64) \
            p += snprintf(tmp + p, (size_t)(cap - p), __VA_ARGS__); \
    } while (0)

    int nz = acpi_thermal_count();
    for (int i = 0; i < nz; i++) {
        int t;
        if (acpi_thermal_read(i, &t) != 0) continue;
        if (!found) _SN("%-24s %s\n", "name", "temp_C");
        char nm[32];
        snprintf(nm, sizeof(nm), "acpi_thermal_zone%d", i);
        int c = t / 10, f = t % 10;
        if (f < 0) f = -f;
        _SN("%-24s %d.%d\n", nm, c, f);
        found++;
    }

    int dt;
    if (intel_dts_available()) {
        int ncpu = energy_core_count_online();
        if (ncpu < 1) ncpu = 1;
        if (ncpu > 64) ncpu = 64;
        for (int c = 0; c < ncpu; c++) {
            if (intel_dts_cpu(c, &dt) != 0) continue;
            if (!found) _SN("%-24s %s\n", "name", "temp_C");
            char nm[32];
            snprintf(nm, sizeof(nm), "cpu_dts%d", c);
            _SN("%-24s %d\n", nm, dt);
            found++;
        }
    }

    if (!found)
        _SN("no sensors available\n");

    #undef _SN

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}

// /proc/slabinfo generator — one row per slab cache: name, in-use objects,
// total objects, object size and slab pages.  A snapshot of the Rust
// allocator's cache list (slab_snapshot).
int _slabinfo_read(uint64_t off, uint32_t size, char *buf) {
    static char tmp[4096];
    int p = 0;
    int cap = (int)sizeof(tmp);

    static slab_info_t infos[64];
    uint32_t n = slab_snapshot(infos, 64);

    #define _SI(...) do { \
        if (p <= cap - 96) \
            p += snprintf(tmp + p, (size_t)(cap - p), __VA_ARGS__); \
    } while (0)

    _SI("%-24s %9s %9s %9s %7s\n", "name", "active", "num_objs", "obj_size", "slabs");
    for (uint32_t i = 0; i < n; i++)
        _SI("%-24s %9u %9u %9u %7u\n", infos[i].name,
            (unsigned)infos[i].active, (unsigned)infos[i].num_objs,
            (unsigned)infos[i].obj_size, (unsigned)infos[i].slabs);

    #undef _SI

    uint32_t len = (uint32_t)p;
    if (off >= len) return 0;
    if (size > len - off) size = (uint32_t)(len - off);
    memcpy(buf, tmp + off, size);
    return (int)size;
}
