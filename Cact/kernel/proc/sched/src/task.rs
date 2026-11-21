// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Task subsystem hub: global state, task list management, shared helpers,
//! and re-exports of the lifecycle submodules (`create`, `exec`, `fork`,
//! `signal`, `sigreturn`).

use core::ffi::c_void;
use core::ptr;
use crate::ffi::{self, MmapTable, PAGE_PRESENT, PAGE_RW, PAGE_SIZE, PAGE_USER};
use crate::mlfq;
use crate::sync::irq_spinlock_t;
use crate::timer_wheel;

pub const MAX_FD: usize = 256;
pub use cact_sync::task_abi::{NSIG, TASK_SHM_MAX, ProcMeta, ProcShared};

pub const USER_CODE_SEL: u32 = 0x1B;
pub const USER_DATA_SEL: u32 = 0x23;
pub const KERNEL_CODE_SEL: u32 = 0x08;
pub const KERNEL_DATA_SEL: u32 = 0x10;

pub const SIGKILL:  u32 = 1 << 0;
pub const SIGTERM:  u32 = 1 << 1;
pub const SIGSTOP:  u32 = 1 << 2;
pub const SIGCONT:  u32 = 1 << 3;
pub const SIGPIPE:  u32 = 1 << 4;
pub const SIGALRM:  u32 = 1 << 5;
pub const SIGCHLD:  u32 = 1 << 6;
pub const SIGFPE:   u32 = 1 << 7;
pub const SIGSEGV:  u32 = 1 << 8;
pub const SIGWINCH: u32 = 1 << 9;
pub const SIGHUP:   u32 = 1 << 10;
pub const SIGINT:   u32 = 1 << 11;
pub const SIGQUIT:  u32 = 1 << 12;
pub const SIGILL:   u32 = 1 << 13;
pub const SIGTRAP:  u32 = 1 << 14;
pub const SIGABRT:  u32 = 1 << 15;
pub const SIGBUS:   u32 = 1 << 16;
pub const SIGUSR1:  u32 = 1 << 17;
pub const SIGUSR2:  u32 = 1 << 18;
pub const SIG_UNCATCHABLE: u32 = SIGKILL | SIGSTOP;

pub const SIG_DFL: u32 = 0;
pub const SIG_IGN: u32 = 1;

// Kernel stacks are one contiguous allocation that grows down.  They must be
// bigger than a single page: syscall handoffs, the VFS, and now in-kernel
// crypto (the DRBG, and webpki's X.509 chain validation) all run on the
// caller's kernel stack, and 4 KiB was not enough room for that chain.
//
// 16 KiB was not enough either.  Measured against the built kernel, the
// `/dev/crypto` X.509 path is
//   syscall entry (176 B) → syscall_handler → sys_ioctl → _crypto_ioctl
//   (1.2 KiB) → cact_x509_verify (5.7 KiB) → webpki build_chain_inner
//   (968 B per certificate in the path, recursing up to MAX_SUB_CA_COUNT = 6)
//   → the signature algorithm (sig::verify 2.7 KiB + the P-384/P-256
//   projective mul 3.3/2.2 KiB, or RSA through num-bigint).
// A routine two/three-certificate chain already sums to ≈16.7 KiB and a
// six-deep one to ≈19.7 KiB, and an IRQ nests on the same stack on top of
// that.  An overflow runs past the base straight into the heap block below —
// the canary only *reports* that afterwards, as a flood of "heap list magic
// corrupted".  32 KiB covers the measured worst case with room for the IRQ.
pub const KERNEL_STACK_SIZE: usize = 32768;
pub const KERNEL_BASE: u32 = 0xC000_0000;

/// Canary words at the base of every kernel stack.  A stack that runs past its
/// base silently overwrites whatever the allocator placed after it, so this is
/// the one place that can notice the overflow instead of the damage it does.
pub const KERNEL_STACK_CANARY: u32 = 0x5A5A_5A5A;

/// Allocate a kernel stack with the canary painted at its base.
///
/// # Safety
///
/// `kstack_alloc` itself has no preconditions; the returned pointer must be passed to
/// `kstack_free` exactly once and must not be used as a stack before it is initialised.
pub unsafe fn kstack_alloc() -> *mut u32 {
    // 16-byte aligned: the SysV ABI keeps RSP 16-aligned across a call and the
    // compiler emits `movaps` for it, so a stack that is only 8-aligned would
    // fault the first time a task spills SSE state.  `kfree` recognises the
    // aligned block through the back-pointer `kmalloc_aligned` leaves.
    let p = cact_mm::kmalloc_aligned(KERNEL_STACK_SIZE, 16) as *mut u32;
    if !p.is_null() {
        // SAFETY: `p` is a live `KERNEL_STACK_SIZE` block, so its first word is in bounds.
        unsafe { *p = KERNEL_STACK_CANARY };
        // SAFETY: `p` is valid for at least two `u32` words, so this address is in bounds.
        let second = unsafe { p.add(1) };
        // SAFETY: `second` is the second word of that live block.
        unsafe { *second = KERNEL_STACK_CANARY };
    }
    p
}

/// # Safety
///
/// `base` must be null or a pointer previously returned by `kstack_alloc`/`kmalloc` that has
/// not already been freed.
pub unsafe fn kstack_free(base: *mut c_void) {
    // SAFETY: `base` is null-checked and, per the contract, is a live allocation from
    // `kstack_alloc`, so `kfree` is called on a valid block.
    unsafe {
        if !base.is_null() {
            cact_mm::kfree((base) as *mut u8);
        }
    }
}

/// 1 while the stack's canary is intact.
///
/// # Safety
///
/// `base` must be null or point to a live kernel-stack allocation of at least two `u32` words.
pub unsafe fn kstack_ok(base: *mut c_void) -> bool {
    if base.is_null() {
        return true;
    }
    let p = base as *const u32;
    // SAFETY: `base` is non-null and points to a live kernel-stack allocation (see # Safety), so
    // the first canary word is in bounds.
    let first = unsafe { *p };
    // SAFETY: that allocation is at least two `u32` words, so this address is in bounds.
    let second_ptr = unsafe { p.add(1) };
    // SAFETY: `second_ptr` is the second word of the live allocation.
    let second = unsafe { *second_ptr };
    first == KERNEL_STACK_CANARY && second == KERNEL_STACK_CANARY
}

/// Report a kernel stack that has run past its base.  The damage is already
/// done by then — this is about naming it instead of letting it surface later
/// as a mystery somewhere else.  Reported once.
pub fn task_check_kernel_stack() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static REPORTED: AtomicBool = AtomicBool::new(false);
    let t = current_task();
    if t.is_null() || REPORTED.load(Ordering::Relaxed) {
        return;
    }
    // SAFETY: `t` is the live current task (non-null checked above).
    let p = unsafe { (*t).proc };
    if p.is_null() {
        return;
    }
    // SAFETY: `p` is the live `ProcMeta` of `t`.
    let stack_base = unsafe { (*p).stack_base };
    // SAFETY: `stack_base` is the live kernel-stack pointer of the current task.
    let ok = unsafe { kstack_ok(stack_base) };
    if !ok {
        REPORTED.store(true, Ordering::Relaxed);
        // SAFETY: `printk` takes a static NUL-terminated byte string.
        unsafe {
            ffi::printk(c"\x01\x32sched: KERNEL STACK OVERFLOW (canary destroyed)\n".as_ptr().cast())
        };
    }
}

pub const EXEC_MAX_ARGS:   usize = 256;
pub const EXEC_MAX_ENVS:   usize = 256;
pub const EXEC_MAX_STRLEN: usize = 4096;

pub const USER_STACK_PAGES: u32 = 4;
pub const USER_STACK_BYTES: u32 = USER_STACK_PAGES * PAGE_SIZE;

pub use cact_sync::task_abi::{TaskShmAttach, TaskState, TaskStruct};

pub use crate::ffi::VfsNode;

/// The task running on the calling CPU.  Backed by [`crate::percpu`] so every
/// core has its own running-task pointer.
#[inline]
pub fn current_task() -> *mut TaskStruct {
    crate::percpu::current()
}

/// Set the calling CPU's running task.
#[inline]
pub fn set_current_task(t: *mut TaskStruct) {
    crate::percpu::set_current(t);
}

#[no_mangle]
pub static mut task_list_head: *mut TaskStruct = ptr::null_mut();

#[no_mangle]
pub static mut next_pid: u32 = 1;

#[export_name = "scheduler_lock"]
pub static mut SCHEDULER_LOCK: irq_spinlock_t = irq_spinlock_t::new();

static mut task_list_tail: *mut TaskStruct = ptr::null_mut();

/// Append `t` to the scheduler's global task list.
///
/// # Safety
///
/// `t` must be null or a live, exclusively owned `TaskStruct`; the caller must hold
/// `SCHEDULER_LOCK` (or be single-threaded), because the list is shared scheduler state.
pub unsafe fn task_list_add(t: *mut TaskStruct) {
    if t.is_null() {
        return;
    }
    // SAFETY: `t` is non-null and live (see # Safety), so clearing its link is in bounds.
    unsafe { (*t).next = ptr::null_mut() };
    // SAFETY: `task_list_tail` is a scheduler-owned global, read under the caller's
    // `SCHEDULER_LOCK` (see # Safety).
    let tail = unsafe { task_list_tail };
    if tail.is_null() {
        // SAFETY: `task_list_head` is a scheduler-owned global, mutated under the caller's lock.
        unsafe { task_list_head = t };
        // SAFETY: `task_list_tail` is a scheduler-owned global, mutated under the caller's lock.
        unsafe { task_list_tail = t };
    } else {
        // SAFETY: `tail` is the last live element of the list, so writing its link is in bounds.
        unsafe { (*tail).next = t };
        // SAFETY: `task_list_tail` is a scheduler-owned global, mutated under the caller's lock.
        unsafe { task_list_tail = t };
    }
}

/// Unlink `t` from the scheduler's global task list.
///
/// # Safety
///
/// `t` must be null or a live `TaskStruct` currently on the scheduler task list; the caller must
/// hold `SCHEDULER_LOCK` (or be single-threaded), because the list is shared scheduler state.
pub unsafe fn task_list_remove(t: *mut TaskStruct) {
    if t.is_null() {
        return;
    }
    // SAFETY: `task_list_head` is a scheduler-owned global, read under the caller's lock.
    if unsafe { task_list_head }.is_null() {
        return;
    }

    let mut prev: *mut TaskStruct = ptr::null_mut();
    // SAFETY: `task_list_head` is a scheduler-owned global, read under the caller's lock.
    let mut cur = unsafe { task_list_head };

    while !cur.is_null() {
        if cur == t {
            // SAFETY: `t` is non-null and live (see # Safety).
            let t_next = unsafe { (*t).next };
            if prev.is_null() {
                // SAFETY: `task_list_head` is a scheduler-owned global, mutated under the
                // caller's lock.
                unsafe { task_list_head = t_next };
            } else {
                // SAFETY: `prev` was reached by walking the list, so it is a live task.
                unsafe { (*prev).next = t_next };
            }
            // SAFETY: `task_list_tail` is a scheduler-owned global, read here.
            let tail = unsafe { task_list_tail };
            if tail == t {
                // SAFETY: mutated under the caller's lock.
                unsafe { task_list_tail = prev };
            }
            // SAFETY: `t` is live, so clearing its link is in bounds.
            unsafe { (*t).next = ptr::null_mut() };
            return;
        }
        prev = cur;
        // SAFETY: `cur` was reached by walking the list, so it is a live task.
        cur = unsafe { (*cur).next };
    }
}

pub fn find_task_by_pid(pid: u32) -> *mut TaskStruct {
    // SAFETY: `task_list_head` is a scheduler-owned global; all callers hold `SCHEDULER_LOCK`, so
    // the list is stable while it is walked here.
    let mut cur = unsafe { task_list_head };
    while !cur.is_null() {
        // SAFETY: `cur` is a live task on the list.
        let cur_pid = unsafe { (*cur).pid };
        if cur_pid == pid {
            return cur;
        }
        // SAFETY: `cur` is live, so its link is in bounds.
        cur = unsafe { (*cur).next };
    }
    ptr::null_mut()
}

pub(crate) fn ustack_phys_by_idx(p: &ProcMeta, idx: usize) -> *mut c_void {
    if idx == 0 {
        p.ustack_phys
    } else {
        p.ustack_phys_extra[idx - 1]
    }
}

pub(crate) fn ustack_kernel_byte_mut(p: &ProcMeta, uva: u64) -> *mut u8 {
    let base = p.ustack_virt;
    let off = uva.wrapping_sub(base) as usize;
    debug_assert!(off < USER_STACK_BYTES as usize);
    let pi = off / PAGE_SIZE as usize;
    let po = off % PAGE_SIZE as usize;
    // SAFETY: `p` is a live `ProcMeta`; `pi`/`po` are the page/offset split of `uva`, and callers
    // pass a `uva` inside this process's mapped user-stack window, so the returned pointer lies
    // inside one of the stack's backing pages.
    unsafe { ustack_phys_by_idx(p, pi).cast::<u8>().add(po) }
}

/// Store one 8-byte word of the initial user-stack image.
pub(crate) fn ustack_write_u64(p: &ProcMeta, uva: u64, val: u64) {
    // SAFETY: `ustack_kernel_byte_mut` yields a pointer inside a user-stack backing page for the
    // caller-supplied in-window `uva`, and callers only pass 8-byte-aligned addresses (the stack
    // slots they step by 8), so the 8-byte store is aligned and in bounds.
    unsafe {
        *(ustack_kernel_byte_mut(p, uva) as *mut u64) = val;
    }
}

pub(crate) fn map_user_stack_in_pd(pd: *mut u64, p: &ProcMeta) {
    if pd.is_null() {
        return;
    }
    // SAFETY: `pd` is null-checked and, per the contract, a live page directory owned by the
    // task; `p` is a live `ProcMeta` whose `ustack_phys`/`ustack_phys_extra` hold this process's
    // stack pages (the VAs `kalloc` handed out, so `vmm_v2p` gives the frames the entries take),
    // so each `vmm_map` is handed a real physical page.
    unsafe {
        for i in 0..USER_STACK_PAGES {
            let vaddr = p.ustack_virt.wrapping_add((i as u64).wrapping_mul(PAGE_SIZE as u64));
            let phys = cact_mm::vmm_v2p(ustack_phys_by_idx(p, i as usize) as *const u8);
            cact_mm::vmm_map(pd, vaddr, phys, (PAGE_USER | PAGE_RW | PAGE_PRESENT) as i32);
        }
    }
}

pub(crate) fn free_user_stack_pages(p: &mut ProcMeta) {
    for i in 0..USER_STACK_PAGES as usize {
        let pn = ustack_phys_by_idx(p, i);
        if !pn.is_null() {
            // SAFETY: the frame is live and PMM-managed; this call releases exactly one reference to it.
            unsafe { cact_mm::free_page(pn as *mut u8) };
        }
    }
    p.ustack_phys = ptr::null_mut();
    p.ustack_phys_extra = [ptr::null_mut(); 3];
}

pub(crate) fn task_zero_init(t: *mut TaskStruct, p: *mut ProcMeta) -> bool {
    if t.is_null() || p.is_null() {
        return false;
    }
    // SAFETY: `t` is a freshly allocated `TaskStruct` block, so zeroing its whole extent is in
    // bounds.
    unsafe { ffi::memory_set(t as *mut c_void, 0, core::mem::size_of::<TaskStruct>()) };
    // SAFETY: `p` is a freshly allocated `ProcMeta` block, so zeroing its whole extent is in
    // bounds.
    unsafe { ffi::memory_set(p as *mut c_void, 0, core::mem::size_of::<ProcMeta>()) };

    // SAFETY: `t` is a fresh, exclusively owned `TaskStruct`, now zeroed.
    let t = unsafe { &mut *t };
    // SAFETY: `p` is a fresh, exclusively owned `ProcMeta`, now zeroed.
    let p = unsafe { &mut *p };

    let fds = cact_mm::kmalloc(core::mem::size_of::<ffi::TaskFdTable>()) as *mut ffi::TaskFdTable;
    if fds.is_null() {
        return false;
    }
    // SAFETY: `fds` is a fresh block of exactly `TaskFdTable`'s size; zeroing it is in bounds.
    unsafe { ffi::memory_set(fds as *mut c_void, 0, core::mem::size_of::<ffi::TaskFdTable>()) };
    p.fds = fds;

    let mmap_tbl = cact_mm::kmalloc(core::mem::size_of::<MmapTable>()) as *mut MmapTable;
    if mmap_tbl.is_null() {
        // SAFETY: `fds` is a live allocation owned here, so releasing it is sound.
        unsafe { cact_mm::kfree((fds as *mut c_void) as *mut u8) };
        p.fds = ptr::null_mut();
        return false;
    }
    // SAFETY: `mmap_tbl` is a fresh `MmapTable`-sized block.
    unsafe { cact_mm::mmap_table_init(mmap_tbl) };
    p.mmap_table = mmap_tbl;

    t.state      = TaskState::Ready;
    t.priority   = mlfq::MLFQ_LEVEL_INTERACTIVE;
    t.time_slice = mlfq::MLFQ_QUANTUM[mlfq::MLFQ_LEVEL_INTERACTIVE as usize];
    t.proc       = p as *mut ProcMeta;
    p.cwd[0]     = b'/';
    for slot in p.signal_handlers.iter_mut() {
        *slot = SIG_DFL as u64;
    }
    // No alternate signal stack until sigaltstack() installs one (POSIX starts
    // in the SS_DISABLE state; signal_flags are already zero from the memset).
    p.altstack_flags = 2;
    true
}

/// Allocate a thread group's shared state, holding one reference.
///
/// The address space, fd table and mmap table are shared by pointer; the
/// value-typed `mm` tracker and the `brk` bounds live here so every thread of
/// the group accounts allocations in one place.  Released by
/// [`proc_shared_free`] when the last member is reaped.
///
/// # Safety
///
/// `page_dir` must be null or a live address space owned by the new thread group.
#[no_mangle]
pub unsafe extern "C" fn proc_shared_alloc(page_dir: *mut u64) -> *mut ProcShared {
    let s = cact_mm::kmalloc(core::mem::size_of::<ProcShared>()) as *mut ProcShared;
    if s.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `s` is a fresh allocation of exactly `ProcShared`'s size, so zeroing it is in
    // bounds.
    unsafe { ffi::memory_set(s as *mut c_void, 0, core::mem::size_of::<ProcShared>()) };
    // SAFETY: `s` is a fresh, exclusively owned `ProcShared`, now zeroed.
    let sr = unsafe { &mut *s };
    sr.refcount = 1;
    sr.mm.page_dir = page_dir;
    s
}

/// Take one more reference on a thread group's shared state.
///
/// # Safety
///
/// `s` must be null or a live `ProcShared`; the caller must hold `SCHEDULER_LOCK`
/// (or be single-threaded), so the increment cannot race another one.
#[no_mangle]
pub unsafe extern "C" fn proc_shared_ref(s: *mut ProcShared) {
    if s.is_null() {
        return;
    }
    // SAFETY: `s` is non-null and, per the contract, a live `ProcShared`; `refcount` is in
    // bounds and the caller's `SCHEDULER_LOCK` serializes the read/write pair.
    let r = unsafe { (*s).refcount };
    // SAFETY: as above.
    unsafe { (*s).refcount = r.wrapping_add(1) };
}

/// Release one reference; returns `true` when the caller released the last one.
///
/// # Safety
///
/// `s` must be null or a live `ProcShared`; the caller must hold `SCHEDULER_LOCK`,
/// which serializes this against every other unref (all reaping happens under it).
pub unsafe fn proc_shared_unref_locked(s: *mut ProcShared) -> bool {
    if s.is_null() {
        return true;
    }
    // SAFETY: `s` is non-null and live; `refcount` is in bounds and the caller's `SCHEDULER_LOCK`
    // serializes it.
    let r = unsafe { (*s).refcount };
    let r = r.saturating_sub(1);
    // SAFETY: as above.
    unsafe { (*s).refcount = r };
    r == 0
}

/// Release a thread group's shared state (tracker array and address space).
///
/// # Safety
///
/// `s` must be null or an exclusively owned `ProcShared` whose refcount reached zero.
pub unsafe fn proc_shared_free(s: *mut ProcShared) {
    if s.is_null() {
        return;
    }
    // SAFETY: `s` is live and owned here; freeing its tracker releases the process page array and
    // the address space it names.
    unsafe { cact_mm::proc_free_pages(core::ptr::addr_of_mut!((*s).mm)) };
    // SAFETY: `s` is the live allocation owned here.
    unsafe { cact_mm::kfree((s as *mut c_void) as *mut u8) };
}

/// # Safety
///
/// Must be called exactly once during single-threaded boot, before any other code touches the
/// scheduler globals or `SCHEDULER_LOCK`.
#[no_mangle]
pub unsafe extern "C" fn task_init() {
    // Single-threaded boot entry: this is the scheduler's own per-CPU state, written before any
    // other CPU or interrupt can observe it (see # Safety).
    set_current_task(ptr::null_mut());
    // SAFETY: as above.
    unsafe { task_list_head = ptr::null_mut() };
    // SAFETY: as above.
    unsafe { task_list_tail = ptr::null_mut() };
    // SAFETY: as above.
    unsafe { next_pid = 1 };

    // SAFETY: initialises the scheduler's own spinlock before it is ever used.
    unsafe { crate::sync::irq_spinlock_init(&raw mut SCHEDULER_LOCK) };
    mlfq::mlfq_init();
    timer_wheel::timer_wheel_global_init();
    // SAFETY: `printk` takes a static NUL-terminated byte string.
    unsafe { ffi::printk(c"\x01\x36sched: MLFQ, timer wheel, scheduler lock\n".as_ptr().cast()) };
}

/// Allocate and initialise a bare idle task: pid 0, ring-0, running, with no
/// address space and no `ProcMeta`.  The BSP's fallback context and every AP's
/// fallback context are built from this.
///
/// # Safety
///
/// Must be called during single-threaded bring-up (boot, or an AP before that
/// AP runs any other code).
pub unsafe fn alloc_idle_task() -> *mut TaskStruct {
    let idle = cact_mm::kmalloc(core::mem::size_of::<TaskStruct>()) as *mut TaskStruct;
    if idle.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `idle` is a fresh allocation of exactly `TaskStruct`'s size; zeroing it is in
    // bounds.
    unsafe { ffi::memory_set(idle as *mut c_void, 0, core::mem::size_of::<TaskStruct>()) };

    // SAFETY: `idle` is a fresh, exclusively owned `TaskStruct`, now zeroed.
    let idle_t = unsafe { &mut *idle };
    idle_t.pid            = 0;
    idle_t.state          = TaskState::Running;
    idle_t.is_kernel      = 1;
    idle_t.page_directory = ptr::null_mut();
    idle_t.proc           = ptr::null_mut();
    idle_t.next           = idle;
    idle_t.priority       = mlfq::MLFQ_LEVEL_BACKGROUND;
    idle_t.ticks_used     = 0;
    idle
}

/// # Safety
///
/// Must be called once from single-threaded boot after `task_init`, with interrupts disabled.
#[no_mangle]
pub unsafe extern "C" fn init_scheduler() -> i32 {
    // SAFETY: single-threaded boot; `alloc_idle_task` only allocates and initialises a task.
    let idle = unsafe { alloc_idle_task() };
    if idle.is_null() {
        // SAFETY: `printk` takes a static NUL-terminated byte string.
        unsafe { ffi::printk(c"\x01\x33sched: cannot allocate idle task\n".as_ptr().cast()) };
        return -1;
    }

    crate::percpu::set_idle_for(0, idle);
    set_current_task(idle);
    // SAFETY: boot-time writes to the scheduler globals, before interrupts are enabled.
    unsafe { task_list_head = idle };
    // SAFETY: as above.
    unsafe { task_list_tail = idle };

    // SAFETY: `printk` takes a static NUL-terminated byte string.
    unsafe { ffi::printk(c"\x01\x36sched: idle task pid 0, circular run queue\n".as_ptr().cast()) };
    0
}

/// Highest mapped *user* VA below the mmap window, one page past it (the brk
/// start).  Returns 0 when nothing user-visible is mapped.
///
/// A four-level walk: a page-table entry names a frame, and the kernel reaches
/// frames through the direct map, so every table is entered via `vmm_p2v`.  The
/// bound excludes the kernel's own entries — the image (`PML4[511]`), the direct
/// map (`PML4[256]`) and the MMIO windows — which all sit at or above
/// `0xBF00_0000`, and only `PAGE_USER` mappings are counted.
pub(crate) fn calc_highest_mapped_va(pd: *mut u64) -> u32 {
    const PAGE_PS: u64 = 1 << 7;
    const ENTRY_MASK: u64 = !0xFFF;
    const LIMIT: u64 = 0xBF00_0000;   /* MMAP_LIMIT */
    if pd.is_null() {
        return 0;
    }
    for pml4i in (0..512).rev() {
        if ((pml4i as u64) << 39) >= LIMIT {
            continue;
        }
        // SAFETY: `pd` is a live PML4 and `pml4i < 512`.
        let e0 = unsafe { *pd.add(pml4i) };
        if e0 & PAGE_PRESENT as u64 == 0 {
            continue;
        }
        let pdpt = cact_mm::vmm_p2v(e0 & ENTRY_MASK) as *const u64;
        for pdpti in (0..512).rev() {
            if ((pml4i as u64) << 39) | ((pdpti as u64) << 30) >= LIMIT {
                continue;
            }
            // SAFETY: `pdpt` is a live PDPT reached through the direct map.
            let e1 = unsafe { *pdpt.add(pdpti) };
            if e1 & PAGE_PRESENT as u64 == 0 {
                continue;
            }
            let pdt = cact_mm::vmm_p2v(e1 & ENTRY_MASK) as *const u64;
            for pdi in (0..512).rev() {
                // SAFETY: `pdt` is a live page directory reached through the direct map.
                let e2 = unsafe { *pdt.add(pdi) };
                if e2 & PAGE_PRESENT as u64 == 0 || e2 & PAGE_USER as u64 == 0 {
                    continue;
                }
                let base =
                    ((pml4i as u64) << 39) | ((pdpti as u64) << 30) | ((pdi as u64) << 21);
                if e2 & PAGE_PS != 0 {
                    if base < LIMIT {
                        return (base + 0x20_0000) as u32;   /* 2 MiB page */
                    }
                    continue;
                }
                let pt = cact_mm::vmm_p2v(e2 & ENTRY_MASK) as *const u64;
                for pti in (0..512).rev() {
                    // SAFETY: `pt` is a live page table reached through the direct map.
                    let e3 = unsafe { *pt.add(pti) };
                    if e3 & PAGE_PRESENT as u64 == 0 || e3 & PAGE_USER as u64 == 0 {
                        continue;
                    }
                    let va = base | ((pti as u64) << 12);
                    if va < LIMIT {
                        return (va + PAGE_SIZE as u64) as u32;
                    }
                }
            }
        }
    }
    0
}

/// Build the empty initial stack image the exec/entry convention expects:
/// `[rsp] = argc`, `[rsp+8] = argv`, `[rsp+16] = envp`, with `argv`/`envp`
/// pointing at lone NULL terminators.  Every entry is an 8-byte word and `rsp`
/// is left 16-byte aligned (the AMD64 process-entry convention).
pub(crate) fn push_empty_args(p: &ProcMeta, sp: &mut u64) {
    // envp array: a single NULL terminator.
    *sp -= 8;
    ustack_write_u64(p, *sp, 0);
    let envp_vaddr = *sp;

    // argv array: a single NULL terminator.
    *sp -= 8;
    ustack_write_u64(p, *sp, 0);
    let argv_vaddr = *sp;

    // Place the 24-byte argc/argv/envp triple so that argc (the initial %rsp)
    // lands 16-byte aligned; the 24-byte triple is not a multiple of 16, so
    // aligning its base here may leave an 8-byte pad below the arrays.
    *sp = (*sp - 24) & !0xF;
    ustack_write_u64(p, *sp + 16, envp_vaddr);
    ustack_write_u64(p, *sp + 8, argv_vaddr);
    ustack_write_u64(p, *sp, 0);
}

/// # Safety
///
/// `t` must be null or a live `TaskStruct`, and the caller must hold `SCHEDULER_LOCK` (or be
/// single-threaded).
#[no_mangle]
pub unsafe extern "C" fn task_set_state(
    t:         *mut TaskStruct,
    _old_state: u32,
    new_state:  u32,
) {
    if t.is_null() {
        return;
    }
    let ns = match new_state {
        0 => TaskState::Ready,
        1 => TaskState::Running,
        2 => TaskState::Sleeping,
        3 => TaskState::Zombie,
        4 => TaskState::Waiting,
        _ => return,
    };
    // SAFETY: `t` is non-null and, per the contract, a live task, so the field write is in
    // bounds.
    unsafe { (*t).state = ns };
    if ns == TaskState::Ready {
        // SAFETY: `t` is live.
        let pri = unsafe { (*t).priority };
        // SAFETY: `t` is live; the caller holds `SCHEDULER_LOCK` (see # Safety).
        unsafe { mlfq::mlfq_enqueue_locked(t, pri) };
    }
}

/// Atomically park the current task in `blocked_state` (a `TASK_*` value)
/// unless a terminating signal has already marked it Zombie.
///
/// The check and the state write happen under `SCHEDULER_LOCK` — the same lock
/// the timer tick holds when it marks the running task Zombie — so the signal
/// cannot slip between them and be overwritten by `Sleeping`/`Waiting`.  Such
/// an overwrite resurrects the task (it gets queued as a sleeper and is
/// rescheduled) and it is never reaped, so a process looping on a blocking call
/// would ignore Ctrl+C forever.
///
/// Returns 0 when the task was parked, 1 when it is Zombie (the caller must
/// then `schedule()` away without parking), -1 for no current task.
///
/// # Safety
///
/// Must be called from task context with `SCHEDULER_LOCK` free.
#[no_mangle]
pub unsafe extern "C" fn task_park_state(blocked_state: u32) -> i32 {
    let ns = match blocked_state {
        2 => TaskState::Sleeping,
        4 => TaskState::Waiting,
        _ => return -1,
    };
    // SAFETY: `SCHEDULER_LOCK` is the scheduler's global spinlock; the caller must not hold it
    // (see # Safety).
    unsafe { crate::sync::irq_spinlock_acquire(&raw mut SCHEDULER_LOCK) };
    let cur = crate::task::current_task();
    if cur.is_null() {
        // SAFETY: the lock was acquired above.
        unsafe { crate::sync::irq_spinlock_release(&raw mut SCHEDULER_LOCK) };
        return -1;
    }
    // SAFETY: `cur` is the live current task (non-null checked above).
    let state = unsafe { (*cur).state };
    if matches!(state, TaskState::Zombie) {
        // SAFETY: the lock was acquired above.
        unsafe { crate::sync::irq_spinlock_release(&raw mut SCHEDULER_LOCK) };
        return 1;
    }
    // SAFETY: `cur` is live and `SCHEDULER_LOCK` is held.
    unsafe { (*cur).state = ns };
    // SAFETY: the lock was acquired above.
    unsafe { crate::sync::irq_spinlock_release(&raw mut SCHEDULER_LOCK) };
    0
}

/// Park the calling task on signal set `set` for POSIX's `sigwait()`, atomically
/// with the pending check: **1** = one of `set` is already pending, so the caller
/// must consume it instead of parking; **2** = the task is Zombie and must not
/// sleep; **0** = parked.
///
/// Taking `SCHEDULER_LOCK` is the whole point: `task_signal_locked` updates
/// `pending_signals` under the same lock, so a signal arriving between the check
/// and the park is either seen by the check or wakes a task that is already
/// Sleeping — it cannot be lost in the gap.
///
/// # Safety
///
/// Must be called from a task context with `SCHEDULER_LOCK` free.
#[no_mangle]
pub unsafe extern "C" fn task_park_sigwait(set: u32) -> u32 {
    // SAFETY: `SCHEDULER_LOCK` is the scheduler's global spinlock; the caller must not hold it
    // (see # Safety).
    unsafe { crate::sync::irq_spinlock_acquire(&raw mut SCHEDULER_LOCK) };
    let cur = crate::task::current_task();
    let mut r = 1u32;
    if !cur.is_null() {
        // SAFETY: `cur` is the live current task (non-null checked above).
        let state = unsafe { (*cur).state };
        if matches!(state, TaskState::Zombie) {
            r = 2;
        } else {
            // SAFETY: `cur` is live, so its `proc` field is in bounds.
            let p = unsafe { (*cur).proc };
            // SAFETY: `p` is that task's live `ProcMeta`.
            let pending = if p.is_null() { 0 } else { unsafe { (*p).pending_signals } };
            if (pending & set) != 0 {
                r = 1;                          // already pending: do not park
            } else {
                if !p.is_null() {
                    // SAFETY: `p` is live and the lock is held, so a signal
                    // raised from here on finds the waiter marked.
                    unsafe { (*p).sigwait_set = set };
                }
                // SAFETY: `cur` is live and the lock is held.
                unsafe { (*cur).state = TaskState::Sleeping };
                r = 0;
            }
        }
    }
    // SAFETY: the lock was acquired above.
    unsafe { crate::sync::irq_spinlock_release(&raw mut SCHEDULER_LOCK) };
    r
}

#[path = "task_create.rs"]
mod task_create;
pub use task_create::*;
#[path = "task_exec.rs"]
mod task_exec;
pub use task_exec::*;
#[path = "task_fork.rs"]
mod task_fork;
pub use task_fork::*;
#[path = "task_signal.rs"]
mod task_signal;
pub use task_signal::*;
#[path = "task_sigreturn.rs"]
mod task_sigreturn;
pub use task_sigreturn::*;
#[path = "task_thread.rs"]
mod task_thread;
pub use task_thread::*;
