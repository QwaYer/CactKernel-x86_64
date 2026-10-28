#include "pat.h"
#include "kernel.h"
#include "klib.h"
#include "memory.h"

/* Module state — populated by pat_init(). */
static int g_pat_present = 0;

/* Kernel page directory (defined by the Rust mm crate as #[no_mangle]). */
extern uint64_t page_directory[512];

static inline void cpuid_raw(uint32_t leaf,
                             uint32_t* eax, uint32_t* ebx,
                             uint32_t* ecx, uint32_t* edx)
{
    __asm__ __volatile__("cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(0));
}

static inline void cpu_invlpg(uint32_t va) {
    __asm__ __volatile__("invlpg (%0)" :: "r"(va) : "memory");
}

#define MSR_IA32_PAT 0x277u

static inline uint64_t rdmsr64(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr64(uint32_t msr, uint64_t val) {
    uint32_t lo = (uint32_t)val, hi = (uint32_t)(val >> 32);
    __asm__ __volatile__("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

void pat_init(void) {
    uint32_t a, b, c, d;
    cpuid_raw(1, &a, &b, &c, &d);
    if (!(d & (1u << PAT_CPUID_EDX_BIT))) {
        pr_warn("%s: unsupported (CPUID.01H:EDX.PAT=0) — framebuffer stays UC\n",
                "pat");
        return;
    }

    /* Program PAT entry 4 = Write-Combining.  pat_enable_wc_for_framebuffer()
     * selects entry 4 (PTE.PAT=1, PCD=0, PWT=0), but the architectural reset
     * value for that entry is Write-Back and firmware is not required to have
     * changed it — an S3 resume resets the MSR again.  Without this the
     * framebuffer would be mapped write-back, and the 3 MB shadow->FB copy in
     * fb_flush() degrades from cache-line writebacks to per-line read-for-
     * ownership traffic against the device. */
    uint64_t pat = rdmsr64(MSR_IA32_PAT);
    uint64_t want = (pat & ~(0x7ull << 32)) | (0x1ull << 32);   /* WC */
    if (want != pat)
        wrmsr64(MSR_IA32_PAT, want);

    /* Report once: a resume re-runs this to restore the MSR. */
    if (g_pat_present)
        return;
    g_pat_present = 1;
    pr_info("%s: per-PTE memory types (WC) available\n", "pat");
}

int pat_available(void) {
    return g_pat_present;
}

int pat_enable_wc_for_framebuffer(uint32_t fb_phys,
                                   uint32_t fb_pitch,
                                   uint32_t fb_height)
{
    if (!fb_phys || !fb_pitch || !fb_height)
        return -2;

    if (!g_pat_present) {
        return -1;   /* pat_init already reported the reason */
    }

    fb_phys &= ~0xFFFu;

    uint32_t fb_size = fb_pitch * fb_height;
    fb_size = (fb_size + 0xFFFu) & ~0xFFFu;

    uint32_t end = fb_phys + fb_size;

    /* Set WC on the framebuffer's pages through the kernel's own map.  In long
     * mode that map is four-level and its RAM/MMIO window is mapped with 2 MiB
     * pages, so the cache bits live in the page-directory entry rather than a
     * PTE; vmm_set_kernel_cache() walks to whichever of the two describes the
     * address.  The upper half of every process map shares these tables, so one
     * pass suffices. */
    for (uint32_t va = fb_phys; va < end; va += PAGE_SIZE) {
        /* PAT set, PCD|PWT clear → (PAT=1, PCD=0, PWT=0) selects PAT entry 4 =
         * Write-Combining (WC). */
        vmm_set_kernel_cache(va, PAGE_PAT, PAGE_PCD | PAGE_PWT);
        cpu_invlpg(va);
    }

    return 0;   /* success reported by kernel.c's framebuffer line */
}
