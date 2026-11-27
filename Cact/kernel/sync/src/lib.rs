// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 CactOS Project

//! Kernel synchronization primitives for Cact (`cact_sync`).
//!
//! Provides sleeping mutexes and counting semaphores that cooperate with the
//! scheduler (`schedule`, MLFQ enqueue) when a contended lock must sleep.  The
//! low-level spinlocks they build on, and the `extern "C"` surface to the C
//! kernel and the scheduler, live in `kernel_rust` — the graph's one `unsafe`
//! crate — so this crate carries no `unsafe` of its own.  Types such as
//! [`task_abi::TaskStruct`] mirror the C ABI and are validated from the `sched`
//! crate via compile-time offset checks.

#![no_std]
#![forbid(unsafe_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
// The C-ABI entry points this crate's thunks expose still have to be FFI-safe.
#![deny(improper_ctypes, improper_ctypes_definitions)]

pub mod kernel_types;
pub mod task_abi;

mod mutex;
mod sched_link;
mod semaphore;
mod spinlock;

// The lock primitives themselves live in `kernel_rust::sync` (asm + interior
// mutability); re-exported so `cact_sync::spinlock_t` and friends keep working.
pub use kernel_rust::sync::{irq_spinlock_t, spinlock_t, IrqLock};
pub use kernel_types::{MmapTable, ProcPageTracker, TaskFdTable, VfsNode};
pub use mutex::*;
pub use semaphore::*;
pub use spinlock::*;
pub use task_abi::{ProcMeta, ProcShared, TaskShmAttach, TaskState, TaskStruct, NSIG, TASK_SHM_MAX};
