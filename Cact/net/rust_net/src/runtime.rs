// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Driver registration, background `net_poll_task` poll thread, and RX entry from the NIC driver.
//!
//! `net_sema` serializes access between the interrupt/RX path and `net_poll_task`.

use kernel_rust::cell::KCell;
use kernel_rust::ptr;

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
static NIC_TABLE: KCell<[NicEntry; NET_NIC_MAX]> = KCell::new([NicEntry::empty(); NET_NIC_MAX]);

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
    NIC_TABLE.with(|table| {
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
    })
}

/// `active_nic` used to be a `#[no_mangle]` static here; it is a C-visible
/// symbol (driver modules read it through ksym), so its storage now lives in
/// `kernel_abi` and this crate reads/writes it via `kernel_rust::net`.
#[allow(non_upper_case_globals)]
pub static my_mac: KCell<MacAddr> = KCell::new(MacAddr { b: [0; 6] });
#[allow(non_upper_case_globals)]
pub static net_sema: KCell<Semaphore> = KCell::new(Semaphore {
    guard: cact_sync::spinlock_t::new(),
    count: core::sync::atomic::AtomicI32::new(0),
    waiters: [core::ptr::null_mut(); 64],
    waiter_count: 0,
});

extern "C" fn net_poll_task() {
    loop {
        net_sema.with(|s| cact_sync::sema_down(s));
        net_poll();
    }
}

/// Periodic timer kick.  smoltcp timers (TCP retransmission, connection timeouts,
/// UDP/ARP caches) only advance while `stack_poll` runs, so a task wakes the poll
/// loop on a fixed cadence even when no NIC IRQ has fired.  The kernel DHCP client
/// that used to drive this wake-up is gone; the poll loop itself stays.
extern "C" fn net_timer_task() {
    loop {
        sched::timer_wheel::sleep_ticks(NET_POLL_PERIOD_TICKS);
        net_sema.with(|s| cact_sync::sema_up(s));
    }
}

/// Poll cadence for the timer task (ticks, 10 ms/tick => 100 ms).
const NET_POLL_PERIOD_TICKS: u32 = 10;

/// `drv` must be non-null and point to a live [`NetDriver`] describing the NIC
/// that is being registered — the `net_driver_t` the C driver keeps for the
/// lifetime of the device.  Its `mac`, `get_mac` and `send`/`poll` fields must
/// be initialised (function pointers either valid or NULL).
pub fn register_netdev(drv: *mut NetDriver) {
    if drv.is_null() {
        return;
    }
    let d = ptr::as_ref(drv);
    let mac = d.mac;
    let name = d.name;

    // Re-registering the same descriptor refreshes its slot; otherwise take the
    // first free one, so order is stable and never has a hole.
    let target = NIC_TABLE.with(|table| {
        let mut target: Option<usize> = None;
        for (i, e) in table.iter_mut().enumerate() {
            if e.used && e.drv == drv {
                return Some(i);
            }
            if !e.used && target.is_none() {
                target = Some(i);
            }
        }
        target
    });
    let Some(i) = target else {
        ffi_kernel::klog_static(ffi_kernel::LOG_WARN, b"net: NIC registry full, NIC dropped\0");
        return;
    };
    NIC_TABLE.with(|table| {
        table[i].used = true;
        table[i].drv = drv;
        table[i].mac = mac;
        table[i].name = name;
    });

    // Bind the NIC to its interface slot (building it on first use), then elect the
    // primary (the lowest live slot) for the legacy getters.  Attaching a second NIC
    // therefore leaves the first one's datapath untouched.
    stack::stack_init();
    stack::iface_attach(i, drv, mac.b);
    let (pdrv, pmac) = NIC_TABLE.with(|table| primary_of(table));
    kernel_rust::net::set_active_nic(pdrv.cast());
    my_mac.with(|m| *m = pmac);
    ffi_kernel::klog_static(ffi_kernel::LOG_OK, b"net: NIC driver registered\0");
}

/// Remove a NIC from the registry (symmetric to registration).  Unloading a
/// secondary NIC leaves the active datapath untouched; unloading the primary
/// promotes the next live NIC, or drops the stack back to loopback-only.
pub fn unregister_netdev(drv: *mut NetDriver) {
    if drv.is_null() {
        return;
    }
    let was_primary = kernel_rust::net::active_nic() == drv.cast();
    let removed_slot = NIC_TABLE.with(|table| {
        let mut removed_slot: Option<usize> = None;
        for (i, e) in table.iter_mut().enumerate() {
            if e.used && e.drv == drv {
                *e = NicEntry::empty();
                removed_slot = Some(i);
                break;
            }
        }
        removed_slot
    });
    let Some(i) = removed_slot else {
        return;
    };
    // Release the NIC from its interface slot.  Slot 0 keeps its interface so
    // loopback and any live sockets survive a NIC unload.
    stack::iface_detach(i);
    // Re-elect the primary.  Only a change of primary updates the legacy getters.
    let (pdrv, pmac) = NIC_TABLE.with(|table| primary_of(table));
    kernel_rust::net::set_active_nic(pdrv.cast());
    if !was_primary {
        return;
    }
    my_mac.with(|m| *m = pmac);
    if pdrv.is_null() {
        // No NIC left: rebuild the stack loopback-only, so the departed interface's
        // sockets and configuration do not linger (matches single-NIC behaviour).
        stack::stack_teardown();
        stack::stack_init();
    }
}

/// Number of registered NICs (live entries in the registry).
pub fn rust_net_nic_count() -> i32 {
    NIC_TABLE.with(|table| table.iter().filter(|e| e.used).count() as i32)
}

/// Interface slot the `index`-th live NIC is bound to (0-based registry slot), or
/// -1 when out of range.  This is the slot its L3 state (address, sockets) lives
/// under in `stack`.
pub fn rust_net_nic_slot(index: u32) -> i32 {
    match nic_slot_for_index(index) {
        Some(s) => s as i32,
        None => -1,
    }
}

/// Copy the `index`-th registered NIC's MAC into `out[6]`.  Returns 0 on
/// success, -1 when `index` is out of range or `out` is NULL.
///
/// `out` may be null (the call then returns -1); if non-null it must point to at
/// least 6 writable bytes.
pub fn rust_net_nic_mac(index: u32, out: *mut u8) -> i32 {
    if out.is_null() {
        return -1;
    }
    let Some(slot) = nic_slot_for_index(index) else {
        return -1;
    };
    let mac = NIC_TABLE.with(|table| table[slot].mac);
    ptr::copy_nonoverlapping(mac.b.as_ptr(), out, 6);
    0
}

/// Copy the NUL-terminated C string `src` into `out` (at most `cap` bytes),
/// returning the number of bytes before the terminator.
fn copy_cstr(src: *const core::ffi::c_char, out: *mut u8, cap: usize) -> i32 {
    let mut n = 0usize;
    while n + 1 < cap {
        let c = ptr::read(src.wrapping_add(n).cast::<u8>());
        ptr::write(out.wrapping_add(n), c);
        if c == 0 {
            return n as i32;
        }
        n += 1;
    }
    ptr::write(out.wrapping_add(cap - 1), 0);
    (cap - 1) as i32
}

/// `out` may be null (the call then returns -1); if non-null it must point to at
/// least `cap` writable bytes.
pub fn rust_net_nic_ifname(index: u32, out: *mut u8, cap: u32) -> i32 {
    if out.is_null() || cap == 0 {
        return -1;
    }
    let Some(slot) = nic_slot_for_index(index) else {
        return -1;
    };
    let name = NIC_TABLE.with(|table| table[slot].name);
    if name.is_null() {
        return -1;
    }
    copy_cstr(name, out, cap as usize)
}

/// Link state for userspace network managers: 1 while a NIC driver is registered.
pub fn rust_net_link_is_up() -> i32 {
    // `active_nic` is a kernel-lifetime `static mut` pointer; an aligned
    // pointer-sized load cannot tear, and `is_null` only inspects the value.
    if kernel_rust::net::active_nic().is_null() {
        0
    } else {
        1
    }
}

/// Copy the registered NIC's MAC address into `out[6]`.  Returns 0 on success,
/// -1 when no NIC is registered or `out` is NULL.
///
/// `out` may be null (the call then returns -1); if non-null it must point to at
/// least 6 writable bytes.
pub fn rust_net_get_mac(out: *mut u8) -> i32 {
    if out.is_null() {
        return -1;
    }
    if kernel_rust::net::active_nic().is_null() {
        return -1;
    }
    my_mac.with(|m| ptr::copy_nonoverlapping(m.b.as_ptr(), out, 6));
    0
}

/// Copy the registered NIC's interface name into `out` as a NUL-terminated
/// string (at most `cap` bytes).  Returns the number of bytes before the
/// terminator, or -1 when no NIC is registered, `out` is NULL, or `cap` is 0.
///
/// `out` may be null (the call then returns -1); if non-null it must point to at
/// least `cap` writable bytes.
pub fn rust_net_get_ifname(out: *mut u8, cap: u32) -> i32 {
    if out.is_null() || cap == 0 {
        return -1;
    }
    if kernel_rust::net::active_nic().is_null() {
        return -1;
    }
    let name = ptr::as_ref(kernel_rust::net::active_nic().cast::<NetDriver>()).name;
    if name.is_null() {
        return -1;
    }
    copy_cstr(name, out, cap as usize)
}

pub fn net_init() {
    net_sema.with(|s| cact_sync::sema_init_ref(s, 0));
    // Bring the L3 stack up *before* spawning the two tasks, not after: a task
    // created here is immediately runnable and the worker cores are already
    // peer-executing this one shared runqueue (sched/src/smp.rs
    // WORKERS_RUN_TASKS), so a worker could poll a stack that did not exist yet.
    // A later `register_netdev` only attaches the NIC's hardware address to it.
    stack::stack_init();
    let _ = sched::task::spawn(net_poll_task as *const core::ffi::c_void);
    let _ = sched::task::spawn(net_timer_task as *const core::ffi::c_void);
    ffi_kernel::klog_static(
        ffi_kernel::LOG_OK,
        b"net: ready (net_poll_task, RX semaphore, timer kick)\0",
    );
}

/// Hand a received frame to the stack.  Called by NIC drivers (and the
/// `net_receive_packet` alias) from their RX path.  `skb` must be null or a
/// live, initialised [`Skb`] the caller hands over: the stack either queues or
/// frees it exactly once, so the caller must not touch it afterwards.
pub fn netif_rx(skb: *mut Skb) {
    stack::stack_enqueue_rx(skb);
}

/// Stable alias exported for loadable NIC driver modules (see `net_shim.c`).
/// Same ownership contract as [`netif_rx`].
pub fn net_receive_packet(skb: *mut Skb) {
    netif_rx(skb);
}

/// Wake `net_poll_task` after a NIC RX IRQ (stable alias for driver modules).
pub fn net_driver_irq_wake() {
    net_sema.with(|s| cact_sync::sema_up(s));
}

pub fn net_poll() {
    stack::stack_poll();
}
