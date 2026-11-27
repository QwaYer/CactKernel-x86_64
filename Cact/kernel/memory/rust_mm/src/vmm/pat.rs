// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Page Attribute Table (PAT) driver — per-page memory type via the PAT bit.
//!
//! PAT supersedes variable-range MTRRs for fine-grained cache control: instead
//! of programming physical-address-range registers (which require disabling
//! caches and a WBINVD), bit 7 of a PTE (`PAGE_PAT`) together with the existing
//! PCD/PWT bits selects one of eight memory types programmed in the IA32_PAT MSR
//! (0x277):
//!
//!   Index  PAT:PCD:PWT   Type    Encoding
//!   ------ ------------  ------- ---------
//!   0      0:0:0         WB      0x06    — Normal RAM (write-back)
//!   1      0:0:1         WT      0x04
//!   2      0:1:0         UC-     0x07
//!   3      0:1:1         UC      0x00    — MMIO (unchanged from legacy)
//!   4      1:0:0         WC      0x01    — Framebuffer write-combining
//!   5      1:0:1         WP      0x05
//!   6      1:1:0         UC-     0x07
//!   7      1:1:1         UC      0x00
//!
//! Entry 4 — the one the framebuffer mapping selects — is programmed to WC.  Its
//! architectural reset value is WB, firmware is not required to have changed it,
//! and an S3 resume resets the MSR, so [`pat_init`] sets it explicitly on every
//! (re)initialisation.
//!
//! The MSR and CPUID accesses stay in C (`cact_rdmsr` / `cact_wrmsr` /
//! `cact_cpuid`); this module is the policy.  The page-table edit goes through
//! `vmm_set_kernel_cache`, which knows a large-page entry carries its PAT
//! selection in bit 12 rather than bit 7.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::ffi::{
    cact_cpuid, cact_rdmsr, cact_wrmsr, LOG_OK, LOG_WARN, PAGE_PAT, PAGE_PCD, PAGE_PWT, PAGE_SIZE,
};
use crate::safe::{flush_tlb, klog_msg};
use crate::vmm::paging::vmm_set_kernel_cache;

/// IA32_PAT — the MSR holding the eight 3-bit memory types.
const MSR_IA32_PAT: u32 = 0x277;
/// CPUID leaf 1 EDX bit 16 = PAT support.
const PAT_CPUID_EDX_BIT: u32 = 16;

/// Set once a CPU has confirmed PAT support; read by
/// [`pat_enable_wc_for_framebuffer`].  APs booting concurrently only ever set it,
/// and the flag carries no data, so a relaxed access is enough.
static PAT_PRESENT: AtomicBool = AtomicBool::new(false);

/// Raw CPUID for one leaf/subleaf.
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let (mut eax, mut ebx, mut ecx, mut edx) = (0u32, 0u32, 0u32, 0u32);
    cact_cpuid(leaf, subleaf, &mut eax, &mut ebx, &mut ecx, &mut edx);
    (eax, ebx, ecx, edx)
}

/// Detect PAT support via CPUID, program PAT entry 4 to Write-Combining, and log
/// the capability once.  Safe to call before any framebuffer activity, and again
/// after a resume or during AP bring-up — the MSR is per-CPU, so every CPU needs
/// the write, while only the first call logs.
#[unsafe(no_mangle)]
pub extern "C" fn pat_init() {
    let (_eax, _ebx, _ecx, edx) = cpuid(1, 0);
    if edx & (1 << PAT_CPUID_EDX_BIT) == 0 {
        klog_msg(
            LOG_WARN,
            c"pat: unsupported (CPUID.01H:EDX.PAT=0) — framebuffer stays UC".as_ptr() as *const u8,
        );
        return;
    }

    // Program PAT entry 4 = Write-Combining (bits 34:32).  The framebuffer map
    // selects entry 4 (PAT=1, PCD=0, PWT=0), but that entry's reset value is
    // Write-Back and a resume restores it, so write it on every call.
    let pat = cact_rdmsr(MSR_IA32_PAT);
    let want = (pat & !(0x7u64 << 32)) | (0x1u64 << 32);
    if want != pat {
        cact_wrmsr(MSR_IA32_PAT, want);
    }

    // Report once: a resume re-runs this to restore the MSR.
    if PAT_PRESENT.swap(true, Ordering::Relaxed) {
        return;
    }
    klog_msg(
        LOG_OK,
        c"pat: per-PTE memory types (WC) available".as_ptr() as *const u8,
    );
}

/// Mark the framebuffer range as Write-Combining by setting the PAT bit and
/// clearing PCD|PWT on every page of `[fb_va, fb_va + pitch*height)`, which
/// selects PAT entry 4 (WC).  `fb_va` is the framebuffer's *virtual* address
/// (the direct-map VA `fb_get_buffer()` returns), not its physical address: the
/// mapping the kernel itself uses is the one whose cache policy matters.
///
/// Also used after a resume to re-apply the bits and drop the stale
/// translations.  Returns 0 on success, -1 when PAT is unsupported, -2 for bad
/// arguments.
#[unsafe(no_mangle)]
pub extern "C" fn pat_enable_wc_for_framebuffer(fb_va: u64, fb_pitch: u32, fb_height: u32) -> i32 {
    if fb_va == 0 || fb_pitch == 0 || fb_height == 0 {
        return -2;
    }
    if !PAT_PRESENT.load(Ordering::Relaxed) {
        return -1; // pat_init already reported the reason
    }

    let fb_va = fb_va & !0xFFF;
    let fb_size = ((fb_pitch as u64) * (fb_height as u64) + 0xFFF) & !0xFFF;
    let end = fb_va + fb_size;

    // The framebuffer is reached through the direct map, whose device pages are
    // 2 MiB, so the cache bits live in the page-directory entry rather than a
    // PTE; vmm_set_kernel_cache rewrites whichever of the two describes the
    // address.  PML4[256] is shared by every process map, so one pass suffices.
    let mut va = fb_va;
    while va < end {
        vmm_set_kernel_cache(va, PAGE_PAT as u64, (PAGE_PCD | PAGE_PWT) as u64);
        flush_tlb(va);
        va += PAGE_SIZE as u64;
    }
    0
}
