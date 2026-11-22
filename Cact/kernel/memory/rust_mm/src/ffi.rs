#![allow(dead_code)]
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project


//! Physical layout constants, PTE/PDE flags, `extern "C"` kernel entry points, and boot MMAP types.
//!
//! This is the single source of truth for sizes and symbols shared between `rust_mm` and C.

use core::cell::UnsafeCell;

/// A `Sync`-safe transparent wrapper for `UnsafeCell<T>`, used for `extern` statics
/// that are mutated by C code under spinlock protection.
///
/// # Safety
///
/// All access through [`SyncMut::get`] is `unsafe` — the caller must ensure
/// the kernel's spinlock protocol is observed.
#[repr(transparent)]
pub struct SyncMut<T>(UnsafeCell<T>);

// SAFETY: kernel guarantees access is serialised via IrqSpinlock.
unsafe impl<T: Send> Sync for SyncMut<T> {}

impl<T> SyncMut<T> {
    pub fn get(&self) -> *mut T {
        self.0.get()
    }
}

pub const PAGE_SIZE: u32 = 4096;

/// Physical address where the kernel is loaded (1 MB mark).
pub const MEM_START: u32 = 0x0010_0000;

/// ---------------------------------------------------------------------------
/// Physical-address layout
/// ---------------------------------------------------------------------------
///
/// The PMM is 64-bit: it indexes whatever the Multiboot2 MMAP reports, so RAM
/// below the 32-bit PCI hole *and* above 4 GiB is managed.  `PCI_HOLE_START` is
/// only the default MMIO base and the floor for the fixed kernel windows; the
/// real RAM/MMIO boundary (`pmm::ram_end()`) and the direct map's extent are
/// discovered at boot.
///
///   0x0000_0000 – 0x000F_FFFF :  1 MB  BIOS / IVT / ROM (reserved)
///   0x0010_0000 – ~0x003F_FFFF :       kernel text + BSS + static page tables
///   reservation end – +16 MB  :        heap window
///   ...                       :        managed RAM (bitmap sized from the map)
///   0xC000_0000 – 0xFFFF_FFFF :        default 32-bit PCI/MMIO hole (uncached)
///   0x1_0000_0000 – ...       :        high RAM (managed) and 64-bit MMIO
/// ---------------------------------------------------------------------------
/// The user/kernel virtual-address split (3 GiB user / 1 GiB kernel), and the
/// *default* physical MMIO base when the Multiboot2 map yields none.
///
/// The real RAM/MMIO boundary is discovered at boot (`pmm::ram_end()`): a board
/// can have usable RAM above this address, up to its PCI hole (e.g.
/// 0xE000_0000 = 3.5 GiB).  Everything at or above `ram_end()` *below* the
/// 32-bit hole is device MMIO.
pub const PCI_HOLE_START: u32 = 0xC000_0000;

/// End of the 32-bit physical address space.  The PMM no longer caps at it, but
/// the direct map treats `[ram_end, 4 GiB)` as device space (uncached), and the
/// low PCI hole ends here on every ACPI/PC machine.
pub const LOW_MEM_END: u64 = 0x1_0000_0000;

/// Sanity cap on a single object's frame-array length (memfd/GEM, address
/// spaces): 64 GiB worth of 4 KiB frames.  The PMM itself is sized from the boot
/// map at run time, so this only bounds a per-object array, never RAM.
pub const PMM_MAX_FRAMES: u32 = 1 << 24;

/// Heap starts right after the hard-reserved low-memory region.
pub const HEAP_START: u32 = 0x2000_0000;
pub const HEAP_SIZE: u32 = 16 * 1024 * 1024;  /* 16 MB heap window */
pub const HEAP_MAGIC: u32 = 0xDEAD_BEEF;

/// Hard reservation: every physical page below RESERVED_END is permanently
/// marked "used" in the PMM bitmap so it is never handed out via kalloc().
///
/// 0 … 512 MB covers:
///   BIOS / IVT / ROM        0x0000_0000 – 0x000F_FFFF
///   Kernel text/data/BSS    0x0010_0000 – (kernel_end, 24 MB cctkfs stage)
///   Static page-tables BSS  up to 0x00BF_FFFF
///   Low user VA region      `USER_HEAP_START` (0x0800_0000) … ELF image +
///                           `brk` heap, which overlaps the reservation and so
///                           must not collide with a handed-out frame.
///                           (Boot modules raise the live value past this
///                           anyway — see `pmm_reserve_boot_images`.)
pub const RESERVED_END: u32 = 0x2000_0000;

/// Maximum number of MMAP entries copied from the MB2 boot info.
pub const MB2_MMAP_MAX_ENTRIES: usize = 128;
pub const MB2_MMAP_TYPE_AVAILABLE: u32 = 1;

pub const PAGE_PRESENT: u32 = 0x001;
pub const PAGE_RW:      u32 = 0x002;
pub const PAGE_USER:    u32 = 0x004;
/// Bit 8 in a PDE — marks a page table as privately allocated for this
/// process (as opposed to a shared static kernel page table).  The CPU
/// ignores this bit in PDEs; we use it to decide which page tables to
/// free in vmm_free_address_space and to COW-copy in vmm_fork.
/// Bit 8 is chosen because it is CPU-ignored for non-leaf PDEs (PS=0),
/// while bit 9 (0x200) is reserved for PAGE_COW on PTEs.
pub const PDE_PRIVATE:  u32 = 0x100;
/// Bit 3 — Page Write-Through (PWT).  Set for MMIO/PCI-hole PTEs so that
/// writes are not held in write buffers.  Also reused as PAGE_SWAPPED marker
/// when PRESENT=0 (non-overlapping use: hw only checks PWT when PRESENT=1).
pub const PAGE_PWT:     u32 = 0x008;
/// Alias: software swap marker reuses bit 3 (safe — PRESENT=0 when swapped).
pub const PAGE_SWAPPED: u32 = 0x008;
/// Bit 4 — Page Cache Disable (PCD).  Set for MMIO/PCI-hole PTEs so that
/// reads/writes bypass L1/L2 cache and reach device registers directly.
pub const PAGE_PCD:     u32 = 0x010;
/// Bit 7 — Page Attribute Table (PAT) *in a 4 KiB PTE*.  Together with PCD/PWT
/// selects a memory type from the IA32_PAT MSR.  (PAT=1,PCD=0,PWT=0) → entry 4
/// = WC.  In a 2 MiB/1 GiB entry this bit is `PAGE_PS` instead and the PAT
/// selection sits in bit 12 — `vmm_set_kernel_cache` re-targets the request for
/// that shape.  Used by the PAT driver (`vmm::pat`).
pub const PAGE_PAT:     u32 = 0x080;
pub const PTE_ACCESSED: u32 = 0x020;
pub const PAGE_COW:     u32 = 0x200;
pub const PAGE_DEMAND:  u32 = 0x400;
pub const PAGE_ZERO:    u32 = 0x800;

pub const USER_STACK_TOP: u32 = 0xC0000000;
pub const USER_STACK_LIMIT: u32 = 0xBF000000;
/// Lowest user virtual address: below this is the low identity-mapped kernel
/// area.  Mirrors `USER_SPACE_START` in `core/syscall/validate.h`.
pub const USER_SPACE_START: u32 = 0x08000000;
/// Low user region: the ELF image plus the `brk` heap (`USER_BRK_MAX_GROWTH`
/// caps how far it can reach).  Its addresses are inside the low reservation
/// (`RESERVED_END`), so nothing here can shadow a kernel frame.
pub const USER_HEAP_START: u32 = 0x08000000;
pub const USER_HEAP_LIMIT: u32 = 0x80000000;

pub const PROT_NONE: i32 = 0x0;
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;
pub const PROT_EXEC: i32 = 0x4;
pub const MAP_SHARED: i32 = 0x01;
pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_FIXED: i32 = 0x10;
pub const MAP_ANON: i32 = 0x20;
/// `do_mmap`'s failure return.  It has to be all ones in *pointer* width: the
/// old 32-bit 0xFFFFFFFF zero-extends to 0x0000_0000_FFFF_FFFF, which neither
/// the C `MAP_FAILED` (`(void*)-1`) nor ld.so's `(u8*)-1` check recognises, so a
/// failed mapping silently looked like a success and the caller used the bogus
/// pointer (or blitted into unmapped memory).
pub const MAP_FAILED: usize = usize::MAX;
pub const MMAP_BASE: u32 = 0x80000000;
pub const MMAP_LIMIT: u32 = 0xBF000000;
pub const MMAP_MAX_REGIONS: usize = 256;
// The shared array size must stay in step with this crate's constant.
const _: () = assert!(MMAP_MAX_REGIONS == cact_sync::kernel_types::MMAP_MAX_REGIONS);

pub const SHM_VA_BASE: u32 = 0xA0000000;
pub const SHM_VA_LIMIT: u32 = 0xB0000000;
pub const SHM_MAX_PAGES: usize = 64;
pub const SHM_MAX_SEGMENTS: usize = 32;
pub const TASK_SHM_MAX: usize = 16;
pub const IPC_CREAT: i32 = 0x0200;
pub const IPC_EXCL: i32 = 0x0400;
pub const IPC_PRIVATE: i32 = 0;
pub const IPC_RMID: i32 = 0;
pub const IPC_STAT: i32 = 2;
pub const SHM_RDONLY: i32 = 0x1000;
pub const SHM_RND: i32 = 0x2000;

pub const MAX_FD: usize = 256;
pub const NSIG: usize = 19;
pub const SIGKILL: u32 = 1 << 0;
pub const SIGSEGV: u32 = 1 << 8;
/// si_code for a signal the kernel generated itself (a fault).
pub const SI_KERNEL: u32 = 0x80;

pub const SLAB_MAX_OBJ_SIZE: u32 = 2048;
pub const SLAB_MIN_OBJ_SIZE: u32 = 8;
pub const SLAB_NAME_LEN: usize = 32;

pub const SWAP_MAX_SLOTS: u32 = 65536;
pub const SWAP_BITMAP_SIZE: u32 = SWAP_MAX_SLOTS / 8;
pub const SWAP_DATA_START_LBA: u32 = 1;

pub const LOG_OK: u32 = 0;
pub const LOG_WARN: u32 = 1;
pub const LOG_ERROR: u32 = 2;
pub const LOG_FAIL: u32 = 3;

pub const COLOR_LIGHT_RED: u32 = 0xFF5555;

pub const TASK_READY: u32 = 0;
pub const TASK_RUNNING: u32 = 1;
pub const TASK_SLEEPING: u32 = 2;
pub const TASK_ZOMBIE: u32 = 3;
pub const TASK_WAITING: u32 = 4;
pub const TASK_STOPPED: u32 = 5;

pub const PROC_INITIAL_PAGES: u32 = 256;
pub const PROC_GROW_STEP: u32 = 256;

/// ---------------------------------------------------------------------------
/// Four-level paging (long mode)
/// ---------------------------------------------------------------------------
///
/// A virtual address names its entry at each level with nine bits, from the
/// PML4 down: PML4 (`vaddr[47:39]`) → PDPT (`[38:30]`) → PD (`[29:21]`) → PT
/// (`[20:12]`), and the twelve bits left over are the offset inside the page.
/// The kernel's 32-bit address layout keeps every address below 4 GiB, so the
/// whole of it lives under PML4[0] — but each level still has to be walked, and
/// a PD or PDPT entry may name a *large* page instead of the next table
/// (`PAGE_PS`), which is how the kernel maps its own half.
///
/// The walk itself lives in `crate::vmm::paging::walk`, which creates the
/// missing tables on demand and splits a large page when a caller needs a
/// 4 KiB mapping inside one.

#[inline(always)]
pub fn pml4_index(vaddr: u64) -> u32 {
    ((vaddr >> 39) & 0x1FF) as u32
}

#[inline(always)]
pub fn pdpt_index(vaddr: u64) -> u32 {
    ((vaddr >> 30) & 0x1FF) as u32
}

#[inline(always)]
pub fn pd_index(vaddr: u64) -> u32 {
    ((vaddr >> 21) & 0x1FF) as u32
}

#[inline(always)]
pub fn pt_index(vaddr: u64) -> u32 {
    ((vaddr >> 12) & 0x1FF) as u32
}

/// Bit 7 of a PD or PDPT entry: the entry maps a *large* page (2 MiB at the PD
/// level, 1 GiB at the PDPT level) instead of pointing at the next table.  In a
/// PTE the same bit is PAT, which is why the kernel's large pages carry no PAT
/// bit.
pub const PAGE_PS: u32 = 0x080;

/// Physical address a 2 MiB large-paged PD entry maps `vaddr` to.
#[inline(always)]
pub fn large_page_phys(entry: u64, vaddr: u64) -> u64 {
    (entry & !(LARGE_PAGE_SIZE as u64 - 1)) | (vaddr & (LARGE_PAGE_SIZE as u64 - 1))
}

/// Size of the kernel's large pages, and of one page-directory entry's span.
pub const LARGE_PAGE_SIZE: u32 = 0x20_0000;

#[inline(always)]
pub fn page_offset(vaddr: u64) -> u64 {
    vaddr & 0xFFF
}

#[repr(C)]
pub struct IrqSpinlock {
    pub spin_locked: u32,
    pub saved_flags: u32,
}

#[repr(C)]
pub struct VfsNode {
    _opaque: [u8; 0],
}

/// Mirror of `struct context_frame` in task.h: what an entry stub leaves on the
/// stack — the fifteen registers (ISR_SAVE in Cact/kernel/core/context.inc
/// pushes them, so the order is fixed), int_no, err_code, and the five slots
/// the CPU pushes itself.
#[repr(C)]
pub struct ContextFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub int_no: u64,
    pub err_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[repr(C)]
pub struct ShmAttachment {
    pub shm_id: i32,
    pub shm_vaddr: u32,
}

#[repr(C)]
pub struct ShmInfo {
    pub shm_segsz: u32,
    pub shm_cpid: u32,
    pub shm_lpid: u32,
    pub shm_nattch: u32,
}

// The kernel-wide definitions live in `cact_sync` (the shared-types crate);
// re-exported here so an `MmapTable`/`ProcPageTracker` pointer has one Rust
// type in `sched`, `cact_mm` and every other kernel Rust crate.
pub use cact_sync::kernel_types::{MmapRegion, MmapTable, ProcPageTracker};
pub use cact_sync::task_abi::ProcShared;

#[repr(C)]
pub struct TaskFdTable {
    pub fd_table:   [*mut VfsNode; MAX_FD],
    pub fd_offset:  [u32; MAX_FD],
    pub fd_flags:   [u32; MAX_FD],
    pub fd_cloexec: [u32; MAX_FD],
}

#[repr(C)]
pub struct TaskStruct {
    pub esp:            u32,
    pub page_directory: *mut u64,
    pub fpu_context_ptr: *mut u8,
    pub pid:            u32,
    pub state:          u32,
    pub is_kernel:      u8,
    pub _pad0:          [u8; 3],
    pub next:           *mut TaskStruct,
    pub queue_next:     *mut TaskStruct,
    pub priority:       u32,
    pub time_slice:     u32,
    pub ticks_used:     u32,
    pub proc:           *mut ProcMeta,
}

#[repr(C)]
pub struct ProcMeta {
    pub stack_base:         *mut u8,
    pub ustack_phys:        *mut u8,
    pub ustack_virt:        u64,
    pub ustack_phys_extra:  [*mut u8; 3],
    pub pending_signals:    u32,
    pub signal_mask:        u32,
    pub saved_signal_mask:  u32,
    pub in_sigsuspend:      u8,
    pub _pad1:              [u8; 3],
    pub signal_handlers:    [u64; NSIG],
    pub sigreturn_trampoline: u64,
    pub alarm_ticks:        u32,
    pub itimer_value:       u32,
    pub itimer_interval:    u32,
    pub fds:                *mut TaskFdTable,
    pub mm:                 ProcPageTracker,
    pub mmap_table:         *mut MmapTable,
    pub parent_pid:         u32,
    pub exit_code:          i32,
    pub wait_for_pid:       u32,
    pub brk_start:          u64,
    pub brk_current:        u64,
    pub sleep_until:        u32,
    pub cwd:                [u8; 256],
    pub uid:                u32,
    pub gid:                u32,
    pub euid:               u32,
    pub egid:               u32,
    pub shm_attachments:    [ShmAttachment; TASK_SHM_MAX],
    pub wait_next:          *mut TaskStruct,
    pub pgid:               u32,
    pub sid:                u32,
    pub umask:              u32,
    pub root:               *mut VfsNode,
    // The sched crate's full `ProcMeta` carries the cached exec symbol table
    // here; keep the offsets aligned so `shared` lands at the same place.
    pub exec_base:          u64,
    pub exec_symtab:        *mut u8,
    pub exec_strtab:        *mut u8,
    pub exec_symtab_count:  i32,
    pub tgid:               u32,
    pub is_thread:          u8,
    pub _pad2:              [u8; 3],
    pub shared:             *mut ProcShared,
    pub clr_tid:            u64,
    pub intr_wait:          u8,
    pub _pad3:              [u8; 3],
    // --- sigaltstack (appended after 612; existing offsets above are unchanged) ---
    pub altstack_sp:        u64,
    pub altstack_size:      u32,
    pub altstack_flags:     u32,
    pub signal_flags:       [u32; NSIG],
    // --- TLS (appended after 676; existing offsets above are unchanged) ---
    pub tls_base:           u64,
    // --- signal dispositions (appended after 680) ---
    pub signal_masks:       [u32; NSIG],
    // --- signal sources (appended after 732) ---
    pub signal_codes:       [u32; NSIG],
    pub signal_addr:        u64,
    // --- sigwait()/sigqueue() (appended after 788) ---
    pub sigwait_set:        u32,
    pub signal_value:       u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PfStats {
    pub total_faults: u32,
    pub demand_allocs: u32,
    pub cow_copies: u32,
    pub stack_grows: u32,
    pub zero_pages: u32,
    pub swap_ins: u32,
    pub protection_faults: u32,
    pub invalid_access: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SwapStats {
    pub total_slots: u32,
    pub used_slots: u32,
    pub pages_swapped_out: u32,
    pub pages_swapped_in: u32,
    pub swap_failures: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OomStats {
    pub oom_kills: u32,
    pub pages_reclaimed: u32,
    pub last_killed_pid: u32,
}

/// Flat MMAP entry passed from the C multiboot2 parser.
/// Must match `mb2_mmap_flat_t` in multiboot2.h exactly.
/// base and len are 64-bit to preserve the full MB2 values (PAE-awareness).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Mb2MmapFlat {
    pub base: u64,
    pub len:  u64,
    pub ty:   u32,
}

/// Table of flat MMAP entries.
/// Must match `mb2_mmap_table_t` in multiboot2.h exactly.
#[repr(C)]
pub struct Mb2MmapTable {
    pub entries: [Mb2MmapFlat; MB2_MMAP_MAX_ENTRIES],
    pub count:   u32,
}

// The C side builds this table and the PMM reads it here.  A stride or offset
// mismatch is silent — it once cost the kernel its whole memory map: C's entry
// was `packed` (20 bytes against these 24), which pushed `count` past the
// written range, so it read back as zero and the PMM fell back to guessing.  So
// both sides assert the layout, and `multiboot2.h` asserts its half.
const _: () = assert!(core::mem::size_of::<Mb2MmapFlat>() == 24);
const _: () = assert!(core::mem::offset_of!(Mb2MmapFlat, ty) == 16);
const _: () = assert!(core::mem::offset_of!(Mb2MmapTable, count) == MB2_MMAP_MAX_ENTRIES * 24);

// SAFETY: Each function and static in this block is backed by a C definition
// in the kernel.  All pointer parameters must be non-null and correctly
// aligned.  `task_list_head` and `scheduler_lock` are
// mutated under the scheduler spinlock — callers must hold that lock or be
// in a single-threaded context (boot / IRQ-off) before accessing them.
unsafe extern "C" {
    pub fn printk(msg: *const u8);
    pub fn printk_color(msg: *const u8, color: u32);
    pub fn printk_hex(n: u32);
    pub fn itoa(n: i32, buf: *mut u8);
    pub fn hex_to_ascii(n: u32, buf: *mut u8);

    pub fn irq_spinlock_init(lock: *mut IrqSpinlock);
    pub fn irq_spinlock_acquire(lock: *mut IrqSpinlock);
    pub fn irq_spinlock_release(lock: *mut IrqSpinlock);

    pub fn load_page_directory(dir: *mut u64);
    pub fn enable_paging();

    /// Read/write an MSR (cpu_ops.c, cpu_ops.h).  The kernel's only MSR access;
    /// the PAT driver uses it for IA32_PAT.
    pub fn cact_rdmsr(msr: u32) -> u64;
    pub fn cact_wrmsr(msr: u32, value: u64);
    /// Raw CPUID (cpudev.c, cpudev.h): leaf/subleaf in, the four registers out.
    pub fn cact_cpuid(
        leaf: u32,
        subleaf: u32,
        eax: *mut u32,
        ebx: *mut u32,
        ecx: *mut u32,
        edx: *mut u32,
    );

    pub fn read_vfs(node: *mut VfsNode, off: u64, size: u32, buf: *mut u8) -> i32;

    /// C memfd glue: returns the memfd object handle for an open fd, or -1.
    pub fn memfd_fd_handle(fd: i32) -> i32;

    /// C VFS glue (vfs_ops.c): resolve an fd + mmap offset to a shared backing
    /// object.  Returns 0 and writes the object handle + in-object byte offset
    /// when the fd is backed (memfd, DRM GEM, …); < 0 when it is not, in which
    /// case do_mmap() falls back to a private copy through read().
    pub fn vfs_mmap_resolve(
        fd: i32,
        off: u32,
        len: u32,
        backing_out: *mut i32,
        obj_off_out: *mut u32,
    ) -> i32;

    /// Per-CPU `current_task` accessor supplied by the `sched` crate.
    pub fn cact_current_task_get() -> *mut TaskStruct;
    pub static task_list_head: SyncMut<*mut TaskStruct>;
    pub static scheduler_lock: SyncMut<IrqSpinlock>;

    pub fn task_signal(pid: u32, signal: u32);
    /// Queue a signal *and* record its source (si_code) and fault address.
    pub fn task_signal_code(pid: u32, signal: u32, code: u32, addr: u64);
    /// Apply a task's pending signals' dispositions: a default action
    /// terminates the task, a user handler is left pending for delivery.
    pub fn task_handle_signals(t: *mut TaskStruct);
    pub fn schedule();
    pub fn task_reap();

    pub fn dump_context_frame(regs: *const ContextFrame, fault_addr: u64, signal: u32);
}

// ---------------------------------------------------------------------------
// Inline-asm helpers — encapsulated in safe functions
// ---------------------------------------------------------------------------

/// Read CR2 (page-fault address).  CR2 is 64-bit in long mode.
#[inline(always)]
pub fn read_cr2() -> u64 {
    let val: u64;
    // SAFETY: reading CR2 is side-effect-free.
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) val, options(nomem, nostack)) };
    val
}

/// Read CR3 (current page directory — the PML4 in long mode) as a **kernel VA**.
///
/// CR3 holds the *physical* address of the live PML4; the kernel reaches that
/// frame through the direct map (PML4[256], see [`crate::vmm::paging::p2v`]), so
/// the raw value is translated before it is handed back — a caller dereferences
/// the result (it walks the tables) and would otherwise be relying on the low
/// identity map.
#[inline(always)]
pub fn get_current_pd() -> *mut u64 {
    let val: u64;
    // SAFETY: reading CR3 is side-effect-free.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) val, options(nomem, nostack)) };
    crate::vmm::paging::p2v(val) as *mut u64
}

/// Invalidate a single TLB entry.
#[inline(always)]
pub fn tlb_flush(vaddr: u64) {
    // SAFETY: INVLPG is safe for any address.
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) vaddr, options(nostack)) };
}

/// Flush the entire TLB by reloading CR3.
#[inline(always)]
pub fn tlb_flush_all() {
    // SAFETY: reloading CR3 with the current value only flushes the TLB.
    unsafe {
        core::arch::asm!(
            "mov rax, cr3",
            "mov cr3, rax",
            out("rax") _,
            options(nostack)
        );
    }
}