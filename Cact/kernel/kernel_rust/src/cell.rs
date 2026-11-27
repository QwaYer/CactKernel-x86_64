// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Safe interior-mutable globals.
//!
//! The kernel keeps its mutable state in `static`s.  Rather than every crate
//! touching a `static mut` (an `unsafe` operation everywhere it is named), the
//! state lives in a [`KCell`], which hands out `&mut T` through
//! [`KCell::with`] under the kernel's own serialisation invariant.

use core::cell::UnsafeCell;

/// A `Sync` wrapper over `UnsafeCell<T>` for the kernel's mutable globals.
///
/// The value may only be touched where the kernel serialises access to it:
/// single-threaded bring-up, or under an external lock (the `/dev/chv` run
/// mutex for the hypervisor model).  [`KCell::with`] relies on that invariant,
/// which is what lets callers stay free of `unsafe`.
pub struct KCell<T>(UnsafeCell<T>);

// SAFETY: every access goes through `with`/`get`/`set`, which run only where
// the kernel serialises the cell (single-threaded or under the owning lock).
unsafe impl<T> Sync for KCell<T> {}

impl<T> KCell<T> {
    /// Wrap `value` — usable in a `static` initialiser.
    pub const fn new(value: T) -> Self {
        KCell(UnsafeCell::new(value))
    }

    /// Run `f` with exclusive access to the cell's value.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        // SAFETY: the kernel serialises access to this cell, so no other
        // reference to the value is live for the duration of `f`.
        unsafe { f(&mut *self.0.get()) }
    }

    /// Copy the value out; for `Copy` types only, so no reference can escape.
    pub fn get(&self) -> T
    where
        T: Copy,
    {
        // SAFETY: as in `with`; a by-value read leaves no aliasing reference.
        unsafe { *self.0.get() }
    }

    /// Overwrite the value.
    pub fn set(&self, value: T) {
        // SAFETY: as in `with`; the old value is dropped in place.
        unsafe { *self.0.get() = value };
    }

    /// Pointer to the inner value, for handing to the C side (which takes a
    /// pointer to kernel-lifetime state, e.g. a semaphore).
    pub fn as_ptr(&self) -> *mut T {
        self.0.get()
    }
}
