// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Driver registration, background `net_poll_task` poll thread, and RX entry from the NIC driver.
//!
//! `net_sema` serializes access between the interrupt/RX path and `net_poll_task`.

use crate::ffi_kernel;
use crate::stack;
use crate::types::{MacAddr, NetDriver, Semaphore, Skb};

/// Maximum number of simultaneously registered NICs.
///
/// The registry is a fixed table because it lives in the kernel's static memory:
/// registration is the single-threaded driver bring-up path and never allocates.
pub const NET_NIC_MAX: usize = 4;

/// One registered NIC: the driver descriptor the kernel was handed, plus the MAC
/// and name snapshotted from it at registration.
///
/// The table order is the interface order.  The lowest live slot is the
/// *primary* NIC — the one [`active_nic`] points at and which carries the active
/// L3 datapath.  Further NICs are registered and visible to userspace but stay
/// idle until per-NIC routing attaches them.
#[derive(Clone, Copy)]
pub struct NicEntry {
    pub used: bool,
    pub drv: *mut NetDriver,
    pub mac: MacAddr,
    pub name: *const core::ffi::c_char,
}

impl NicEntry {
    const fn empty() -> Self {
        Self {
            used: false,
            drv: core::ptr::null_mut(),
            mac: MacAddr { b: [0; 6] },
            name: core::ptr::null(),
        }
    }
}

/// Registry of registered NICs.  Mutated only on the single-threaded
/// registration/teardown path (`register_netdev` / `unregister_netdev`) and read
/// from the enumeration syscall paths; every field is a scalar or a pointer, so
/// an aligned load cannot tear.
static mut NIC_TABLE: [NicEntry; NET_NIC_MAX] = [NicEntry::empty(); NET_NIC_MAX];

/// Primary NIC = the lowest-index live registry entry, as `(descriptor, MAC)`;
/// `(null, zeroed)` when no NIC is registered.
fn primary_of(table: &[NicEntry; NET_NIC_MAX]) -> (*mut NetDriver, MacAddr) {
    match table.iter().find(|e| e.used) {
        Some(e) => (e.drv, e.mac),
        None => (core::ptr::null_mut(), MacAddr { b: [0; 6] }),
    }
}

/// Registry slot of the `index`-th *live* NIC (0-based, in registry order), or
/// `None` when `index` is past the last one.  Gaps left by a teardown are
/// skipped, so interface indices stay dense across register/unregister.
fn nic_slot_for_index(index: u32) -> Option<usize> {
    // SAFETY: `NIC_TABLE` is a kernel-lifetime static read from a syscall path;
    // every field is a scalar, so the shared borrow cannot tear.
    let table = unsafe { &*core::ptr::addr_of!(NIC_TABLE) };
    let mut k = 0u32;
    for (i, e) in table.iter().enumerate() {
        if e.used {
            if k == index {
                return Some(i);
            }
            k += 1;
        }
    }
    None
}

#[no_mangle]
pub static mut active_nic: *mut NetDriver = core::ptr::null_mut();
#[no_mangle]
pub static mut my_mac: MacAddr = MacAddr { b: [0; 6] };
#[no_mangle]
pub static mut net_sema: Semaphore = Semaphore {
    guard: cact_sync::spinlock_t::new(),
    count: core::sync::atomic::AtomicI32::new(0),
    waiters: [core::ptr::null_mut(); 64],
    waiter_count: 0,
};

extern "C" fn net_poll_task() {
    loop {
        // SAFETY: semaphore lives for kernel lifetime.
        unsafe {
            ffi_kernel::down(core::ptr::addr_of_mut!(net_sema));
        }
        net_poll();
    }
}

/// Periodic timer kick.  smoltcp timers (TCP retransmission, connection timeouts,
/// UDP/ARP caches) only advance while `stack_poll` runs, so a task wakes the poll
/// loop on a fixed cadence even when no NIC IRQ has fired.  The kernel DHCP client
/// that used to drive this wake-up is gone; the poll loop itself stays.
extern "C" fn net_timer_task() {
    loop {
        // SAFETY: `sched_sleep_ticks` is a kernel service that suspends the
        // calling task for a whole number of ticks; it is safe from task
        // context.
        unsafe { sched::timer_wheel::sched_sleep_ticks(NET_POLL_PERIOD_TICKS) };
        // SAFETY: `net_sema` is a kernel-lifetime semaphore initialised by
        // `net_init`; `up` is the matching kernel C release service.
        unsafe { ffi_kernel::up(core::ptr::addr_of_mut!(net_sema)) };
    }
}

/// Poll cadence for the timer task (ticks, 10 ms/tick => 100 ms).
const NET_POLL_PERIOD_TICKS: u32 = 10;

/// # Safety
///
/// `drv` must be non-null and point to a live [`NetDriver`] describing the NIC
/// that is being registered — the `net_driver_t` the C driver keeps for the
/// lifetime of the device.  Its `mac`, `get_mac` and `send`/`poll` fields must
/// be initialised (function pointers either valid or NULL), because this
/// function reads them and stores `drv` in the crate-wide `active_nic`, which
/// every later TX/RX path dereferences.
#[no_mangle]
pub unsafe extern "C" fn register_netdev(drv: *mut NetDriver) {
    if drv.is_null() {
        return;
    }
    // SAFETY: the caller contract (see # Safety) makes `drv` a valid pointer to
    // a live `NetDriver` whose fields are initialised; this shared borrow ends
    // before any publish below, so nothing mutates it while it is live.
    let d = unsafe { &*drv };
    let mac = d.mac;
    let name = d.name;

    // SAFETY: `NIC_TABLE` is the kernel-lifetime registry, mutated only here and
    // in `unregister_netdev`, both on the single-threaded registration path; the
    // exclusive borrow ends once the slot is filled below.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(NIC_TABLE) };
    // Re-registering the same descriptor refreshes its slot; otherwise take the
    // first free one, so order is stable and never has a hole.
    let mut target: Option<usize> = None;
    for (i, e) in table.iter_mut().enumerate() {
        if e.used && e.drv == drv {
            target = Some(i);
            break;
        }
        if !e.used && target.is_none() {
            target = Some(i);
        }
    }
    let Some(i) = target else {
        ffi_kernel::klog_static(
            ffi_kernel::LOG_WARN,
            b"net: NIC registry full, NIC dropped\0",
        );
        return;
    };
    table[i].used = true;
    table[i].drv = drv;
    table[i].mac = mac;
    table[i].name = name;

    // Bind the NIC to its interface slot (building it on first use), then elect the
    // primary (the lowest live slot) for the legacy getters.  Attaching a second NIC
    // therefore leaves the first one's datapath untouched.
    stack::stack_init();
    stack::iface_attach(i, drv, mac.b);
    // SAFETY: `NIC_TABLE` is mutated only on this single-threaded path; this
    // shared borrow ends before the `active_nic`/`my_mac` stores below.
    let table = unsafe { &*core::ptr::addr_of!(NIC_TABLE) };
    let (pdrv, pmac) = primary_of(table);
    // SAFETY: `active_nic` is a kernel-lifetime `static mut` pointer written
    // only here and in `unregister_netdev`, on this same single-threaded path.
    unsafe { active_nic = pdrv };
    // SAFETY: as above, for the kernel-lifetime `my_mac` static.
    unsafe { my_mac = pmac };
    ffi_kernel::klog_static(ffi_kernel::LOG_OK, b"net: NIC driver registered\0");
}

/// Remove a NIC from the registry (symmetric to registration).  Unloading a
/// secondary NIC leaves the active datapath untouched; unloading the primary
/// promotes the next live NIC, or drops the stack back to loopback-only.
#[no_mangle]
pub extern "C" fn unregister_netdev(drv: *mut NetDriver) {
    if drv.is_null() {
        return;
    }
    // SAFETY: `active_nic` is read on the single-threaded teardown path; an
    // aligned pointer load cannot tear.
    let was_primary = unsafe { active_nic == drv };
    let mut removed_slot: Option<usize> = None;
    // SAFETY: `NIC_TABLE` is mutated only here and in `register_netdev`, on the
    // single-threaded teardown path; the exclusive borrow ends below.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(NIC_TABLE) };
    for (i, e) in table.iter_mut().enumerate() {
        if e.used && e.drv == drv {
            *e = NicEntry::empty();
            removed_slot = Some(i);
            break;
        }
    }
    let Some(i) = removed_slot else {
        return;
    };
    // Release the NIC from its interface slot.  Slot 0 keeps its interface so
    // loopback and any live sockets survive a NIC unload.
    stack::iface_detach(i);
    // Re-elect the primary.  Only a change of primary updates the legacy getters.
    // SAFETY: the shared borrow ends before the publishes below.
    let table = unsafe { &*core::ptr::addr_of!(NIC_TABLE) };
    let (pdrv, pmac) = primary_of(table);
    // SAFETY: `active_nic`/`my_mac` are kernel-lifetime statics written only on
    // this path and in `register_netdev`.
    unsafe { active_nic = pdrv };
    if !was_primary {
        return;
    }
    // SAFETY: as above, for the kernel-lifetime `my_mac` static.
    unsafe { my_mac = pmac };
    if pdrv.is_null() {
        // No NIC left: rebuild the stack loopback-only, so the departed interface's
        // sockets and configuration do not linger (matches single-NIC behaviour).
        // Both calls run on the single-threaded driver teardown path.
        // SAFETY: `stack_teardown`'s caller contract is exactly this path.
        unsafe { stack::stack_teardown() };
        stack::stack_init();
    }
}

/// Number of registered NICs (live entries in the registry).
#[no_mangle]
pub extern "C" fn rust_net_nic_count() -> i32 {
    // SAFETY: `NIC_TABLE` is a kernel-lifetime static read from a syscall path;
    // every field is a scalar, so the shared borrow cannot tear.
    let table = unsafe { &*core::ptr::addr_of!(NIC_TABLE) };
    table.iter().filter(|e| e.used).count() as i32
}

/// Interface slot the `index`-th live NIC is bound to (0-based registry slot), or
/// -1 when out of range.  This is the slot its L3 state (address, sockets) lives
/// under in `stack`.
#[no_mangle]
pub extern "C" fn rust_net_nic_slot(index: u32) -> i32 {
    match nic_slot_for_index(index) {
        Some(s) => s as i32,
        None => -1,
    }
}

/// Copy the `index`-th registered NIC's MAC into `out[6]`.  Returns 0 on
/// success, -1 when `index` is out of range or `out` is NULL.
///
/// # Safety
///
/// `out` may be null (the call then returns -1), but if non-null it must point
/// to at least 6 writable bytes that stay live for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rust_net_nic_mac(index: u32, out: *mut u8) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(slot) = nic_slot_for_index(index) else {
        return -1;
    };
    // SAFETY: `NIC_TABLE` is a kernel-lifetime static; `slot` came from
    // `nic_slot_for_index` and is therefore in bounds.
    let mac = unsafe { (*core::ptr::addr_of!(NIC_TABLE))[slot].mac };
    // SAFETY: `out` is the caller's 6-byte writable buffer (the null check above
    // excluded null) and `mac.b` is a 6-byte array, so the ranges cannot overlap.
    unsafe { core::ptr::copy_nonoverlapping(mac.b.as_ptr(), out, 6) };
    0
}

/// Copy the `index`-th registered NIC's interface name into `out` as a
/// NUL-terminated string (at most `cap` bytes).  Returns the number of bytes
/// before the terminator, or -1 when `index` is out of range, `out` is NULL, or
/// `cap` is 0.
///
/// # Safety
///
/// `out` may be null (the call then returns -1); if non-null it must point to
/// at least `cap` writable bytes that stay live for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rust_net_nic_ifname(index: u32, out: *mut u8, cap: u32) -> i32 {
    if out.is_null() || cap == 0 {
        return -1;
    }
    let Some(slot) = nic_slot_for_index(index) else {
        return -1;
    };
    // SAFETY: `NIC_TABLE` is a kernel-lifetime static; `slot` came from
    // `nic_slot_for_index` and is therefore in bounds.
    let name = unsafe { (*core::ptr::addr_of!(NIC_TABLE))[slot].name };
    if name.is_null() {
        return -1;
    }
    let cap = cap as usize;
    // SAFETY: every in-tree driver points `name` at a `'static` NUL-terminated
    // literal, so byte `n` is in bounds while `n + 1 < cap`; `out` is the
    // caller's `cap`-byte writable buffer (the null / zero-size checks above
    // excluded the degenerate cases).  The loop stops at the terminator or at
    // `cap - 1`, whichever comes first, so it never writes past `out[cap - 1]`.
    unsafe {
        let mut n = 0usize;
        while n + 1 < cap {
            let c = *name.add(n) as u8;
            *out.add(n) = c;
            if c == 0 {
                return n as i32;
            }
            n += 1;
        }
        *out.add(cap - 1) = 0;
        (cap - 1) as i32
    }
}

/// Link state for userspace network managers: 1 while a NIC driver is registered.
#[no_mangle]
pub extern "C" fn rust_net_link_is_up() -> i32 {
    // SAFETY: `active_nic` is a kernel-lifetime `static mut` pointer; an aligned
    // pointer-sized load cannot tear, and `is_null` only inspects the value.
    if unsafe { active_nic.is_null() } {
        0
    } else {
        1
    }
}

/// Copy the registered NIC's MAC address into `out[6]`.  Returns 0 on success,
/// -1 when no NIC is registered or `out` is NULL.
///
/// # Safety
///
/// `out` may be null (the call then returns -1), but if non-null it must point
/// to at least 6 writable bytes that stay live for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rust_net_get_mac(out: *mut u8) -> i32 {
    if out.is_null() {
        return -1;
    }
    // SAFETY: `active_nic` is a kernel-lifetime `static mut` pointer read from a
    // syscall path; an aligned pointer load cannot tear.
    if unsafe { active_nic.is_null() } {
        return -1;
    }
    // SAFETY: `addr_of!` forms a pointer to the live `my_mac.b` static field
    // without creating a reference; `my_mac` is a kernel-lifetime static that no
    // other context writes on this path.
    let src = unsafe { core::ptr::addr_of!(my_mac.b).cast::<u8>() };
    // SAFETY: `src` points to the live 6-byte `my_mac.b` array; `out` is the
    // caller's 6-byte writable buffer (the null check above excluded null), and
    // it comes from the caller so it cannot overlap the static.
    unsafe { core::ptr::copy_nonoverlapping(src, out, 6) };
    0
}

/// Copy the registered NIC's interface name into `out` as a NUL-terminated
/// string (at most `cap` bytes).  Returns the number of bytes before the
/// terminator, or -1 when no NIC is registered, `out` is NULL, or `cap` is 0.
///
/// # Safety
///
/// `out` may be null (the call then returns -1); if non-null it must point to
/// at least `cap` writable bytes that stay live for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn rust_net_get_ifname(out: *mut u8, cap: u32) -> i32 {
    if out.is_null() || cap == 0 {
        return -1;
    }
    // SAFETY: `active_nic` is a kernel-lifetime `static mut` pointer read from a
    // syscall path; an aligned pointer load cannot tear.
    if unsafe { active_nic.is_null() } {
        return -1;
    }
    // SAFETY: the null test above proved `active_nic` points at a live
    // `NetDriver` (it is only cleared by `unregister_netdev`, on the
    // single-threaded teardown path), so reading its `name` field is valid.
    let name = unsafe { (*active_nic).name };
    if name.is_null() {
        return -1;
    }
    let cap = cap as usize;
    // SAFETY: every in-tree driver points `name` at a `'static` NUL-terminated
    // literal, so byte `n` is in bounds while `n < cap`; `out` is the caller's
    // `cap`-byte writable buffer (the null / zero-size checks above excluded the
    // degenerate cases).  The loop stops at the terminator or at `cap - 1`,
    // whichever comes first, so it never writes past `out[cap - 1]`.
    unsafe {
        let mut n = 0usize;
        while n + 1 < cap {
            let c = *name.add(n) as u8;
            *out.add(n) = c;
            if c == 0 {
                return n as i32;
            }
            n += 1;
        }
        *out.add(cap - 1) = 0;
        (cap - 1) as i32
    }
}

#[no_mangle]
pub extern "C" fn net_init() {
    // SAFETY: `net_sema` is a kernel-lifetime semaphore static; `sema_init`
    // initialises it once, before any task can wait on it (this runs once from
    // the single-threaded boot path, after the scheduler exists).
    unsafe { ffi_kernel::sema_init(core::ptr::addr_of_mut!(net_sema), 0) };
    // Bring the L3 stack up *before* spawning the two tasks, not after: a task
    // created here is immediately runnable and the worker cores are already
    // peer-executing this one shared runqueue (sched/src/smp.rs
    // WORKERS_RUN_TASKS), so a worker could poll a stack that did not exist yet.
    // A later `register_netdev` only attaches the NIC's hardware address to it.
    stack::stack_init();
    // SAFETY: `create_task` spawns a kernel task from the given (valid, `'static`)
    // entry point; it is called here on the same single-threaded path.
    unsafe { let _ = sched::task::create_task(net_poll_task as *const core::ffi::c_void); }
    // SAFETY: as above, for the periodic timer task.
    unsafe { let _ = sched::task::create_task(net_timer_task as *const core::ffi::c_void); }
    ffi_kernel::klog_static(
        ffi_kernel::LOG_OK,
        b"net: ready (net_poll_task, RX semaphore, timer kick)\0",
    );
}

/// Hand a received frame to the stack.  Called by NIC drivers (and the
/// `net_receive_packet` alias) from their RX path.
///
/// # Safety
///
/// `skb` must be null or a live, initialised [`Skb`] the caller hands over: the
/// stack either queues or frees it exactly once, so the caller must not touch it
/// afterwards.
#[no_mangle]
pub unsafe extern "C" fn netif_rx(skb: *mut Skb) {
    // SAFETY: this only forwards `skb`; the caller contract above is what makes
    // `stack_enqueue_rx`'s own `# Safety` requirement hold.
    unsafe {
        stack::stack_enqueue_rx(skb);
    }
}

/// Stable alias exported for loadable NIC driver modules (see `net_shim.c`).
///
/// # Safety
///
/// As [`netif_rx`]: `skb` must be null or a live, initialised [`Skb`] that this
/// call takes ownership of.
#[no_mangle]
pub unsafe extern "C" fn net_receive_packet(skb: *mut Skb) {
    // SAFETY: this only forwards `skb`; the caller contract above is what makes
    // `netif_rx`'s own `# Safety` requirement hold.
    unsafe {
        netif_rx(skb);
    }
}

/// Wake `net_poll_task` after a NIC RX IRQ (stable alias for driver modules).
#[no_mangle]
pub extern "C" fn net_driver_irq_wake() {
    // SAFETY: net_sema is a kernel-lifetime static.
    unsafe {
        ffi_kernel::up(core::ptr::addr_of_mut!(net_sema));
    }
}

#[no_mangle]
pub extern "C" fn net_poll() {
    stack::stack_poll();
}
