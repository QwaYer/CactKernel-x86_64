/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "cpudev.h"
#include "kernel.h"

// Long-mode fast-syscall MSRs (extended — 0xC000_xxxx).  SYSCALL/SYSRET is the
// only fast path in long mode (SYSENTER/SYSEXIT was legacy-mode only); the
// entry point is the 64-bit IA32_LSTAR, and STAR supplies the segment bases.
#define AMD_EFER            0xC0000080u
#define AMD_EFER_SCE        (1u << 0)   // SYSCALL/SYSRET enable
#define AMD_STAR            0xC0000081u
#define AMD_LSTAR           0xC0000082u
#define AMD_FMASK           0xC0000084u

static cpu_vendor_t   g_vendor             = CPU_VENDOR_UNKNOWN;
static syscall_mech_t g_syscall_mech       = SYSCALL_MECH_INT80;
static uint32_t       g_features_edx       = 0;
static uint32_t       g_features_ecx       = 0;
static uint32_t       g_features_ext_edx   = 0;
static uint32_t       g_features_leaf7_ebx = 0;
static uint32_t       g_features_leaf7_ecx = 0;
static uint32_t       g_features_leaf7_edx = 0;
static uint32_t       g_features_ext7_edx  = 0;
static int            g_invariant_tsc      = 0;
static char           g_brand[49]          = {0};

static inline void cpuid_raw(uint32_t leaf, uint32_t *eax, uint32_t *ebx,
                              uint32_t *ecx, uint32_t *edx) {
    __asm__ __volatile__("cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(0));
}

static inline void cpuid_raw_subleaf(uint32_t leaf, uint32_t subleaf,
                                      uint32_t *eax, uint32_t *ebx,
                                      uint32_t *ecx, uint32_t *edx) {
    __asm__ __volatile__("cpuid"
        : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
        : "a"(leaf), "c"(subleaf));
}

/* Raw CPUID, exported for the Rust topology decode (sched/src/cpu_topo.rs):
 * leaf+subleaf in, the four registers out.  The Rust side reads leaves 0xB/0x1F
 * (and the leaf 1/4 HTT fallback) and turns the register values into
 * package/core ids with the pure `topology` module. */
void cact_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax, uint32_t *ebx,
                uint32_t *ecx, uint32_t *edx) {
    cpuid_raw_subleaf(leaf, subleaf, eax, ebx, ecx, edx);
}

static inline uint64_t rdmsr(uint32_t msr) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline void wrmsr(uint32_t msr, uint64_t val) {
    uint32_t lo = (uint32_t)val, hi = (uint32_t)(val >> 32);
    __asm__ __volatile__("wrmsr" :: "c"(msr), "a"(lo), "d"(hi));
}

/* The SYSCALL entry stack (`syscall_set_esp0` / `syscall_set_cpu_esp0`) now
 * lives in the scheduler's per-CPU block (Rust, `sched/src/percpu.rs`): the
 * entry reads it from `%gs:8` rather than from a low-memory table indexed by the
 * TR selector, so it no longer needs the `.boot.data` section. */
extern int smp_self_cpu(void);

// CPUID leaf 0 lays the 12-byte vendor ID out as EBX, then EDX, then ECX
// (e.g. "GenuineIntel" = EBX "Genu", EDX "ineI", ECX "ntel").
static int vendor_match(uint32_t ebx, uint32_t ecx, uint32_t edx,
                         const char* s) {
    const unsigned char* b = (const unsigned char*)&ebx;
    const unsigned char* d = (const unsigned char*)&edx;
    const unsigned char* c = (const unsigned char*)&ecx;
    for (int i = 0; i < 4; i++) {
        if (b[i] != (unsigned char)s[i])   return 0;
        if (d[i] != (unsigned char)s[i+4]) return 0;
        if (c[i] != (unsigned char)s[i+8]) return 0;
    }
    return 1;
}

static cpu_vendor_t detect_vendor(void) {
    uint32_t eax, ebx, ecx, edx;
    cpuid_raw(0, &eax, &ebx, &ecx, &edx);

    if (vendor_match(ebx, ecx, edx, "GenuineIntel"))
        return CPU_VENDOR_INTEL;
    if (vendor_match(ebx, ecx, edx, "AuthenticAMD"))
        return CPU_VENDOR_AMD;
    if (vendor_match(ebx, ecx, edx, "CentaurHauls"))
        return CPU_VENDOR_VIA;
    if (vendor_match(ebx, ecx, edx, "HygonGenuine"))
        return CPU_VENDOR_HYGON;
    if (vendor_match(ebx, ecx, edx, "  Shanghai  "))
        return CPU_VENDOR_ZHAOXIN;
    return CPU_VENDOR_UNKNOWN;
}

const char* cpu_vendor_str(cpu_vendor_t vendor) {
    switch (vendor) {
    case CPU_VENDOR_INTEL:   return "Intel";
    case CPU_VENDOR_AMD:     return "AMD";
    case CPU_VENDOR_VIA:     return "VIA";
    case CPU_VENDOR_HYGON:   return "Hygon";
    case CPU_VENDOR_ZHAOXIN: return "Zhaoxin";
    default:                 return "Unknown";
    }
}

const char* cpu_syscall_mech_str(syscall_mech_t mech) {
    switch (mech) {
    case SYSCALL_MECH_SYSENTER: return "SYSENTER/SYSEXIT";
    case SYSCALL_MECH_SYSCALL:  return "SYSCALL/SYSRET";
    default:                    return "int 0x80";
    }
}

cpu_vendor_t   cpu_vendor(void)          { return g_vendor; }
uint32_t       cpu_features_edx(void)     { return g_features_edx; }
uint32_t       cpu_features_ecx(void)     { return g_features_ecx; }
uint32_t       cpu_features_ext_edx(void) { return g_features_ext_edx; }
uint32_t       cpu_features_leaf7_ebx(void) { return g_features_leaf7_ebx; }
uint32_t       cpu_features_leaf7_ecx(void) { return g_features_leaf7_ecx; }
uint32_t       cpu_features_leaf7_edx(void) { return g_features_leaf7_edx; }

int cpu_has_sep(void)    { return !!(g_features_edx & CPU_FEATURE_SEP); }
int cpu_has_syscall(void){ return !!(g_features_ext_edx & CPU_FEATURE_SYSCALL); }
int cpu_has_monitor(void){ return !!(g_features_ecx & CPU_FEATURE_MONITOR); }
int cpu_has_x2apic(void) { return !!(g_features_ecx & CPU_FEATURE_X2APIC); }
int cpu_has_rdrand(void) { return !!(g_features_ecx & CPU_FEATURE_RDRAND); }
int cpu_has_invariant_tsc(void) { return g_invariant_tsc; }
// Leaf 0x15H gives the exact TSC:core-crystal ratio, from which the TSC
// frequency follows once the crystal is known; leaf 0x16H reports the base
// frequency, which is the rate an invariant TSC counts at.  Prefer the exact
// ratio, fall back to the base frequency.  Returns 0 if firmware enumerates
// neither, leaving the caller to use a different clock.
uint64_t cpu_tsc_hz_from_cpuid(void) {
    uint32_t max_leaf;
    cpuid_raw(0, &max_leaf, &(uint32_t){0}, &(uint32_t){0}, &(uint32_t){0});

    if (max_leaf >= 0x15) {
        uint32_t denom, numer, crystal;
        cpuid_raw(0x15, &denom, &numer, &crystal, &(uint32_t){0});
        if (denom && numer && crystal)
            return (uint64_t)crystal * numer / denom;
    }

    if (max_leaf >= 0x16) {
        uint32_t base_mhz;
        cpuid_raw(0x16, &base_mhz, &(uint32_t){0}, &(uint32_t){0}, &(uint32_t){0});
        if (base_mhz)
            return (uint64_t)base_mhz * 1000000ull;
    }

    return 0;
}

const char* cpu_brand_str(void) { return g_brand; }

static void read_brand(void) {
    union {
        char     c[48];
        uint32_t u[12];
    } brand;
    uint32_t eax, ebx, ecx, edx;
    uint32_t leaf;
    for (leaf = 0x80000002; leaf <= 0x80000004; leaf++) {
        cpuid_raw(leaf, &eax, &ebx, &ecx, &edx);
        int i = (int)(leaf - 0x80000002) * 4;
        brand.u[i + 0] = eax;
        brand.u[i + 1] = ebx;
        brand.u[i + 2] = ecx;
        brand.u[i + 3] = edx;
    }
    brand.c[47] = '\0';
    const char *p = brand.c;
    while (*p == ' ') p++;
    for (int i = 0; i < 48 && p[i] != '\0'; i++)
        g_brand[i] = p[i];
    g_brand[47] = '\0';
}

static void detect_leaf7(void) {
    uint32_t max_leaf;
    cpuid_raw(0, &max_leaf, &(uint32_t){0}, &(uint32_t){0}, &(uint32_t){0});
    if (max_leaf < 7)
        return;
    cpuid_raw_subleaf(7, 0, &(uint32_t){0},
                       &g_features_leaf7_ebx,
                       &g_features_leaf7_ecx,
                       &g_features_leaf7_edx);
}

// Invariant (constant-rate) TSC detection.  The CPU must advertise this
// explicitly as CPUID.80000007H:EDX[8] — the architectural bit, which Intel
// implements too.  Nothing else substitutes for it: in particular the mere
// presence of CPUID leaf 15H says nothing about invariance under a
// hypervisor, which may expose the leaf with all-zero fields while masking
// the invtsc bit (QEMU does exactly that with -cpu host).  This matters for
// wall-clock use: without the bit the TSC stops in deep C-states and shifts
// with P-state changes, so a resumed machine reads a stale value and time
// jumps backwards.
static int detect_invariant_tsc(void) {
    uint32_t max_ext;
    cpuid_raw(0x80000000, &max_ext, &(uint32_t){0}, &(uint32_t){0}, &(uint32_t){0});
    if (max_ext >= 0x80000007) {
        cpuid_raw(0x80000007, &(uint32_t){0}, &(uint32_t){0},
                  &(uint32_t){0}, &g_features_ext7_edx);
        if (g_features_ext7_edx & CPU_FEATURE_INV_TSC)
            return 1;
    }
    return 0;
}

int cpudev_init(void) {
    g_vendor = detect_vendor();

    cpuid_raw(1,
              &(uint32_t){0}, &(uint32_t){0},
              &g_features_ecx, &g_features_edx);

    uint32_t max_ext;
    cpuid_raw(0x80000000, &max_ext,
              &(uint32_t){0}, &(uint32_t){0}, &(uint32_t){0});
    if (max_ext >= 0x80000001) {
        cpuid_raw(0x80000001,
                  &(uint32_t){0}, &(uint32_t){0},
                  &(uint32_t){0}, &g_features_ext_edx);
    }

    if (max_ext >= 0x80000004)
        read_brand();

    detect_leaf7();
    g_invariant_tsc = detect_invariant_tsc();

    if (g_brand[0]) {
        if (g_vendor != CPU_VENDOR_UNKNOWN) {
            pr_info("%s: %s %s\n", "cpu", cpu_vendor_str(g_vendor),
                    (char*)cpu_brand_str());
        } else {
            pr_info("%s: %s\n", "cpu", (char*)cpu_brand_str());
        }
    } else {
        pr_info("%s: %s\n", "cpu", cpu_vendor_str(g_vendor));
    }

    // Long mode has exactly one fast-syscall mechanism: SYSCALL/SYSRET (the
    // SYSENTER/SYSEXIT pair is a legacy-mode instruction and went away with the
    // 32-bit entry).  Every x86-64 CPU implements it once EFER.SCE is set.
    g_syscall_mech = SYSCALL_MECH_SYSCALL;
    if (!cpu_has_syscall()) {
        pr_crit("%s: CPU does not advertise SYSCALL — syscalls will NOT work\n", "syscall");
    }

    pr_info("%s: %s\n", "syscall",
            (char*)cpu_syscall_mech_str(g_syscall_mech));

    return 0;
}

int cpu_syscall_commit(void) {
    extern void syscall_entry(void);
    extern uint8_t early_kernel_stack[4096];
    uint64_t boot_rsp = (uint64_t)(uintptr_t)
        (early_kernel_stack + sizeof(early_kernel_stack));

    // Seed this CPU's SYSCALL entry stack (the scheduler overwrites it with the
    // running task's kernel stack on the first context switch).
    {
        int me = smp_self_cpu();
        syscall_set_cpu_esp0((uint32_t)(me < 0 ? 0 : me), boot_rsp);
    }

    // Long-mode fast syscall: EFER.SCE enables SYSCALL/SYSRET, LSTAR is the
    // 64-bit entry point, and STAR carries the segment bases —
    //   STAR[47:32] = SYSCALL CS base (kernel code 0x08; SS = CS + 8 = 0x10)
    //   STAR[63:48] = SYSRET  CS base (unused: the entry returns with IRET).
    // FMASK clears IF on entry (the entry switches stacks off the user stack, so
    // interrupts must stay masked until the kernel stack is loaded) and DF (the
    // C code assumes the direction flag is clear).
    uint64_t efer = rdmsr(AMD_EFER);
    wrmsr(AMD_EFER, efer | AMD_EFER_SCE);

    wrmsr(AMD_LSTAR, (uint64_t)(uintptr_t)syscall_entry);

    uint64_t star = ((uint64_t)0x18 << 48) |   // SYSRET CS base (unused)
                    ((uint64_t)0x08 << 32);    // SYSCALL CS base
    wrmsr(AMD_STAR,  star);
    wrmsr(AMD_FMASK, 0x600);                   // clear IF (bit 9) and DF (bit 10)

    return 0;
}
