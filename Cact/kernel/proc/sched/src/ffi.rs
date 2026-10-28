//! Foreign-function declarations for the C kernel: memory, VMM, ELF, VFS, context switch.
//!
//! `ContextFrame` matches the interrupt stack frame layout on iret/syscall boundaries.

use core::cell::SyncUnsafeCell;
use core::ffi::c_void;

pub use cact_sync::kernel_types::{
    MmapTable, ProcPageTracker, TaskFdTable, VfsNode,
};

/// Mirror of `struct context_frame` in task.h: what an entry stub leaves on the
/// stack — the fifteen registers (ISR_SAVE in Cact/kernel/core/context.inc
/// pushes them, so the order is fixed), int_no, err_code, and the five slots
/// the CPU pushes itself.
#[repr(C)]
pub struct ContextFrame {
    pub r15:      u64,
    pub r14:      u64,
    pub r13:      u64,
    pub r12:      u64,
    pub rbp:      u64,
    pub rbx:      u64,
    pub r11:      u64,
    pub r10:      u64,
    pub r9:       u64,
    pub r8:       u64,
    pub rax:      u64,
    pub rcx:      u64,
    pub rdx:      u64,
    pub rsi:      u64,
    pub rdi:      u64,
    pub int_no:   u64,
    pub err_code: u64,
    pub rip:      u64,
    pub cs:       u64,
    pub rflags:   u64,
    pub rsp:      u64,
    pub ss:       u64,
}

#[repr(C)]
pub struct InterpInfo {
    pub main_entry:  u32,
    pub main_base:   u32,
    pub main_phdr:   u32,
    pub main_phnum:  u32,
    pub interp_base: u32,
}

// SAFETY: All functions and statics are backed by C definitions in the kernel.
// Pointer parameters must be non-null and correctly aligned.  The mutable
// statics (`page_directory`, `tss_entry`, `vfs_root`) are
// read/written under the scheduler spinlock or during boot — callers must
// hold the appropriate lock (or be in a single-threaded context).
unsafe extern "C" {

    pub fn memory_copy(dst: *mut c_void, src: *const c_void, size: usize);
    pub fn memory_set(dst: *mut c_void, val: u8, size: usize);



    pub fn load_elf(
        path:    *const u8,
        pd:      *mut u32,
        tracker: *mut ProcPageTracker,
    ) -> *mut c_void;
    pub fn elf_get_interp_path(path: *const u8, out: *mut u8, out_max: i32) -> i32;
    pub fn load_elf_interp(
        path:        *const u8,
        interp_path: *const u8,
        pd:          *mut u32,
        tracker:     *mut ProcPageTracker,
        info:        *mut InterpInfo,
    ) -> *mut c_void;

    pub fn elf_get_brk_start(node: *mut VfsNode) -> u32;

    pub fn vfs_walk_path(root: *mut VfsNode, path: *const u8) -> *mut VfsNode;
    pub fn vfs_walk_path_follow(
        root: *mut VfsNode,
        path: *const u8,
        err_out: *mut i32,
    ) -> *mut VfsNode;
    pub fn vfs_check_perm(node: *mut VfsNode, perm: u32) -> i32;
    pub fn close_vfs(node: *mut VfsNode);
    pub fn open_vfs(node: *mut VfsNode);

    pub fn file_ref(f: *mut c_void) -> *mut c_void;
    pub fn file_unref(f: *mut c_void) -> i32;




    pub fn switch_to(old_esp: *mut u64, new_esp: u64);
    pub fn switch_paging(pd: *mut u32);

    pub fn kernel_task_trampoline();
    pub fn user_task_trampoline();
    pub fn fork_task_trampoline();

    pub fn printk(s: *const u8);
    pub fn printk_color(s: *const u8, color: u32);
    pub fn itoa(n: i32, buf: *mut u8);
    pub fn hex_to_ascii(n: u32, buf: *mut u8);

    pub static page_directory: SyncUnsafeCell<u32>;       
    pub static tss_entry: SyncUnsafeCell<TssEntry>;
    pub static vfs_root: SyncUnsafeCell<*mut VfsNode>;
    pub static sys_sigreturn_num: u32;

    pub fn elf_load_exec_symtab(path: *const u8, proc: *mut c_void);
    pub fn apic_lapic_id() -> u32;

    pub fn set_idt_gate(n: i32, handler: u64);
    pub fn apic_x2apic_mode() -> bool;
    pub fn apic_send_ipi(dest_lapic: u32, vector: u32) -> i32;

    pub fn gdt_flush(gdt_ptr: u64);
    /// Program the per-task `%fs` base (IA32_FS_BASE) on the calling core.
    pub fn gdt_write_tls(base: u64);
    /// Program the calling core's per-CPU `%gs` base (IA32_GS_BASE) and clear
    /// IA32_KERNEL_GS_BASE, so `swapgs` covers a ring-3 entry/exit.
    pub fn gdt_write_gs_base(base: u64);
    /// Load `sel` into `%fs` on the calling core.
    pub fn gdt_load_fs(sel: u16);
    pub fn idt_reload();
    pub fn apic_ap_online();
    pub fn apic_send_init_ipi(dest_lapic: u32);
    pub fn apic_send_sipi(dest_lapic: u32, vector: u32);

    /// BSP-calibrated LAPIC tick rate (ticks per millisecond); 0 before calibration.
    pub fn lapic_timer_ticks_per_ms() -> u32;
    /// Arm the calling CPU's LAPIC timer at `ticks_per_ms`, periodic on the
    /// scheduler vector.
    pub fn lapic_timer_start_periodic(ticks_per_ms: u32);

    /// Enable x87+SSE (CR0/CR4) on the calling CPU.
    pub fn fpu_global_init() -> i32;
    /// Program the calling CPU's IA32_PAT MSR.
    pub fn pat_init();
    /// Program the calling CPU's fast-syscall MSRs (SYSENTER/STAR/FMASK).
    pub fn cpu_syscall_commit() -> i32;
    /// Non-zero when the CPU advertises MONITOR/MWAIT (CPUID.01H:ECX bit 3).
    pub fn cpu_has_monitor() -> i32;
    /// Raw CPUID: leaf/subleaf in, eax/ebx/ecx/edx out.  Used by the topology
    /// decode (`crate::cpu_topo`).
    pub fn cact_cpuid(leaf: u32, subleaf: u32, eax: *mut u32, ebx: *mut u32,
                      ecx: *mut u32, edx: *mut u32);
    /// Read the processor `_CST` package and publish C-states (ACPI cstates.c).
    pub fn acpi_cstates_probe() -> i32;
}

// Value-only kernel helpers: no pointer arguments and no preconditions, so
// calling them is safe Rust (the *returned* pointer may still need care).
// The `safe` qualifier is what lets their call sites stay out of `unsafe`.
unsafe extern "C" {
    pub safe fn cpu_syscall_mech() -> u32;
    pub safe fn acpi_available() -> i32;
    pub safe fn timer_ticks_get() -> u32;
}


/// Mirror of `struct tss_entry_struct` in gdt.h: the 64-bit TSS, which keeps
/// only the stacks (no saved register image and no `ss0` — the ring-transition
/// stack segment is fixed in long mode).  Packed because the C struct is, so
/// `rsp0` sits at offset 4 as the hardware reads it.
#[repr(C, packed)]
pub struct TssEntry {
    pub reserved0:  u32,
    pub rsp0:       u64,
    pub rsp1:       u64,
    pub rsp2:       u64,
    pub reserved1:  u64,
    pub ist:        [u64; 7],
    pub reserved2:  u64,
    pub reserved3:  u16,
    pub iomap_base: u16,
}

pub const PAGE_PRESENT: u32 = 1 << 0;
pub const PAGE_RW:      u32 = 1 << 1;
pub const PAGE_USER:    u32 = 1 << 2;
pub const PAGE_SIZE:    u32 = 4096;

pub const LOG_OK:    i32 = 0;
pub const LOG_WARN:  i32 = 1;
pub const LOG_ERROR: i32 = 2;
pub const LOG_FAIL:  i32 = 3;

pub const SYSCALL_MECH_INT80:    u32 = 0;
pub const SYSCALL_MECH_SYSENTER: u32 = 1;
pub const SYSCALL_MECH_SYSCALL:  u32 = 2;

pub const KERNEL_BASE: u32 = 0xC000_0000;

#[macro_export]
macro_rules! printk {
    ($s:literal) => {
        unsafe { $crate::ffi::printk(concat!($s, "\0").as_ptr()) }
    };
}

/// # Safety
///
/// `t` must point to a valid, writable `ProcPageTracker`.
#[inline(always)]
pub unsafe fn proc_tracker_init(t: *mut ProcPageTracker) {
    // SAFETY: `t` is a caller-supplied live `ProcPageTracker` (see # Safety), so it can be
    // reborrowed exclusively for the duration of this call.
    let t = unsafe { &mut *t };
    t.pages    = core::ptr::null_mut();
    t.count    = 0;
    t.capacity = 0;
    t.page_dir = core::ptr::null_mut();
}

/// # Safety
///
/// The caller must be in kernel mode and must not disable interrupts in a way that violates an
/// outer critical-section invariant.
#[inline(always)]
pub unsafe fn cli() {
    // SAFETY: `cli` only clears IF on the current CPU and writes no memory.
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }
}

/// # Safety
///
/// The caller must be in kernel mode and must only enable interrupts once the state it is
/// protecting is consistent.
#[inline(always)]
pub unsafe fn sti() {
    // SAFETY: `sti` only sets IF on the current CPU and writes no memory.
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

/// # Safety
///
/// The caller must be in kernel mode with a valid kernel stack.
#[inline(always)]
pub unsafe fn read_eflags() -> u32 {
    // SAFETY: `pushfq; pop` is stack-balanced and only reports the current RFLAGS
    // value (the 64-bit form is the only one long mode encodes).
    unsafe {
        let flags: u64;
        core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, nostack));
        flags as u32
    }
}

/// # Safety
///
/// The caller must be in kernel mode; the instruction has no side effects.
#[inline(always)]
pub unsafe fn pause() {
    // SAFETY: `pause` is a hint instruction that touches no memory and no flags.
    unsafe {
        core::arch::asm!("pause", options(nomem, nostack, preserves_flags));
    }
}