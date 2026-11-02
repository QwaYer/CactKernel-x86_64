/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/*
 * CactOS overrides for ACPICA's platform layer.
 *
 * Included from the END of ACPICA's source/include/platform/acenv.h by
 * tools/cact_acpica_patch.py, so this file wins over both aclinux.h (included
 * earlier by acenv.h) and acenv.h's own #ifndef defaults.  The #undef/#define
 * pairs keep the replacement free of "macro redefined" warnings.
 *
 * Only settings where ACPICA's default is wrong for this kernel are here; why
 * nothing else from the old CactOS platform headers is ported is written down
 * in Cact/drivers/acpi/PLATFORM.md.
 */

#ifndef CACT_ACENV_H
#define CACT_ACENV_H

/*
 * Cache flush before an S-state transition (hwsleep.c / hwesleep.c call this
 * for every sleep state below S4; ACPI spec requires it).  ACPICA's Linux and
 * generic defaults both define it as an empty macro, which leaves dirty
 * write-back lines in place across the transition.
 */
#undef ACPI_FLUSH_CPU_CACHE
#define ACPI_FLUSH_CPU_CACHE()  __asm__ __volatile__("wbinvd" ::: "memory")

/*
 * FACS global lock (ACPI spec 5.2.9) — the lock shared with firmware for the
 * methods that use it (Acquire(GL) in ASL, AcpiAcquireGlobalLock()).  ACPICA's
 * default only pretends to take it, which is fine until firmware actually uses
 * the lock: the caller (evglock.c) then believes it owns a lock it never
 * acquired, and never performs the release handshake.
 *
 * Bit-exact port of ACPICA's own x86 implementation (acwin.h), expressed with
 * atomics instead of inline asm:
 *
 *   Lock word:  bit1 = held, bit0 = "somebody is waiting", bits 2+ = firmware's
 *   state, which the OS must preserve.
 *
 *   acquire: if bit1 was clear we take it (Acquired = 1) and clear bit0; if
 *   bit1 was set we leave the lock alone and set bit0, which is the pending
 *   request evglock.c then waits on until firmware signals GBL_RLS.
 *   release: clear bit0 and bit1, and report the old bit0 as Pending, i.e.
 *   "there was a request outstanding — write GBL_RLS".
 *
 * A NULL FACS is reported as acquired, as acwin.h does.
 */
#undef ACPI_ACQUIRE_GLOBAL_LOCK
#define ACPI_ACQUIRE_GLOBAL_LOCK(GLptr, Acquired)                           \
    do {                                                                    \
        (Acquired) = 1;                                                     \
        if ((GLptr) != NULL) {                                              \
            volatile UINT32 *_cact_gl = &((GLptr)->GlobalLock);             \
            UINT32 _cact_old, _cact_new;                                    \
            do {                                                            \
                _cact_old = __atomic_load_n(_cact_gl, __ATOMIC_ACQUIRE);    \
                _cact_new = (_cact_old & ~1u) | 2u;                         \
                if (_cact_old & 2u) {                                       \
                    _cact_new++;    /* keep firmware's waiters accounted */  \
                }                                                           \
            } while (!__atomic_compare_exchange_n(_cact_gl, &_cact_old,     \
                         _cact_new, 0,                                      \
                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED));              \
            (Acquired) = ((_cact_new & 0xFFu) < 3u) ? 1 : 0;                \
        }                                                                   \
    } while (0)

#undef ACPI_RELEASE_GLOBAL_LOCK
#define ACPI_RELEASE_GLOBAL_LOCK(GLptr, Pending)                            \
    do {                                                                    \
        (Pending) = 0;                                                      \
        if ((GLptr) != NULL) {                                              \
            volatile UINT32 *_cact_gl = &((GLptr)->GlobalLock);             \
            UINT32 _cact_old;                                               \
            do {                                                            \
                _cact_old = __atomic_load_n(_cact_gl, __ATOMIC_ACQUIRE);    \
            } while (!__atomic_compare_exchange_n(_cact_gl, &_cact_old,     \
                         _cact_old & ~3u, 0,                                \
                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED));              \
            (Pending) = (_cact_old & 1u) ? 1 : 0;                           \
        }                                                                   \
    } while (0)

#endif /* CACT_ACENV_H */
