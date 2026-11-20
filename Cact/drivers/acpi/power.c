/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/*
 * power.c — ACPI system power transitions.
 *
 * Owns the kernel's powerdown paths:
 *   - S5 soft-off    (poweroff)   -> AcpiEnterSleepState(S5)
 *   - reset register (reboot)     -> AcpiReset()
 *   - halt                        -> stop the CPU with interrupts off
 *
 * Every destructive path is layered: the ACPI/ACPICA route first, then a
 * direct PM1a/PM1b register write from \_Sx, then the QEMU/Bochs PM1a port
 * convention, then a CPU-level fallback.  A machine with a broken or absent
 * FADT therefore still powers off / resets instead of hanging forever.
 *
 * Suspend-to-RAM (S3) shares the PM1 write but, unlike the one-way paths, has
 * to come back.  Before entering S3 the FACS waking vector is pointed at the
 * wake trampoline (wake.asm, staged on the identity-mapped 0xA000 page) and
 * the state the sleep resets is saved into its info block.  On wake the
 * platform re-enters that page in real mode; the trampoline returns to
 * acpi_suspend_lowlevel(), so acpi_suspend() reads as an ordinary call that
 * merely took a long time.
 */

#include "kernel.h"
#include "klib.h"
#include "acpi.h"
#include "cact_acpi.h"
#include "ktime.h"
#include "apic.h"
#include "cpu_cr.h"
#include "cpudev.h"
#include "gdt.h"
#include "idt.h"
#include "pat.h"
#include "smp.h"

/* Legacy PM1 control register layout (ACPI 1.0): SLP_TYP occupies bits 10-12,
 * SLP_EN is bit 13 of PM1x_CNT. */
#define PM1_SLP_TYP_SHIFT   10
#define PM1_SLP_EN          (1u << 13)

/* QEMU's ACPI PM1a control block for the q35/i440fx machine types, plus the
 * older Bochs-derived port some PC firmware still answers on. */
#define QEMU_PM1A_CNT       0x604
#define BOCHS_PM1A_CNT      0xB004

/* 8042 keyboard controller: pulse the reset line when no ACPI reset exists. */
#define KBC_STATUS_PORT     0x64
#define KBC_IBF             0x02
#define KBC_RESET_CMD       0xFE

static int pm_ready;         /* ACPICA namespace + FADT usable            */
static uint32_t s_state_mask;/* bit Sx set when the \_Sx object is present */

/* ---------------------------------------------------------------------------
 * CPU-level fallbacks
 * ------------------------------------------------------------------------- */

static void cpu_stop(void) __attribute__((noreturn));
static void cpu_stop(void)
{
    __asm__ volatile ("cli");
    for (;;) __asm__ volatile ("hlt");
}

/* Load a null IDT and raise an exception: the double->triple fault resets the
 * CPU when no firmware reset path answered. */
static void triple_fault(void) __attribute__((noreturn));
static void triple_fault(void)
{
    struct __attribute__((packed)) { uint16_t limit; uint32_t base; } idtr = { 0, 0 };
    __asm__ volatile ("lidt %0" :: "m"(idtr));
    __asm__ volatile ("int $0x03");
    cpu_stop();
}

static void kbc_reset(void)
{
    for (int i = 0; i < 100000; i++) {
        if ((inb(KBC_STATUS_PORT) & KBC_IBF) == 0)
            break;
    }
    outb(KBC_STATUS_PORT, KBC_RESET_CMD);
}

static void spin_ms(unsigned ms)
{
    /* ktime is TSC/PM-timer backed and available before ring 3. */
    ktime_busy_wait_us((uint64_t)ms * 1000u);
}

/* Program PM1a/PM1b directly with the \_Sx SLP_TYP values.  Returns 1 when at
 * least the PM1a control block was written. */
static int pm1_write_direct(uint8_t state)
{
    UINT8 ta = 0, tb = 0;
    uint32_t a, b;

    if (!pm_ready)
        return 0;
    if (ACPI_FAILURE(AcpiGetSleepTypeData(state, &ta, &tb)))
        return 0;

    a = AcpiGbl_FADT.Pm1aControlBlock;
    b = AcpiGbl_FADT.Pm1bControlBlock;
    if (!a)
        return 0;

    outw((uint16_t)a, (uint16_t)(((uint32_t)ta << PM1_SLP_TYP_SHIFT) | PM1_SLP_EN));
    if (b)
        outw((uint16_t)b, (uint16_t)(((uint32_t)tb << PM1_SLP_TYP_SHIFT) | PM1_SLP_EN));
    return 1;
}

int acpi_sleep_states(uint32_t *mask)
{
    uint32_t m = 0;

    if (pm_ready) {
        for (uint8_t s = ACPI_STATE_S0; s <= ACPI_STATE_S5; s++) {
            UINT8 a, b;
            if (ACPI_SUCCESS(AcpiGetSleepTypeData(s, &a, &b)))
                m |= (1u << s);
        }
    }
    if (mask)
        *mask = m;
    return pm_ready ? 0 : -1;
}

/* ---------------------------------------------------------------------------
 * Suspend-to-RAM (S3)
 * ------------------------------------------------------------------------- */

/* The wake trampoline is staged on the identity-mapped 0xA000 page (paging.rs)
 * and reads its saved-state block from the top of that page.  Both the page and
 * the block layout must match wake.asm. */
#define WAKE_TRAMP_PHYS   0xA000u
#define WAKE_INFO_PHYS    0xAF00u
#define WAKE_INFO         ((volatile uint64_t *)(uintptr_t)WAKE_INFO_PHYS)

/* Info-block field indices (byte offset / 8); must match wake.asm. */
#define WI_CR0       0
#define WI_CR3       1
#define WI_CR4       2
#define WI_PAT       3
#define WI_XCR0      4
#define WI_FS_BASE   5
#define WI_GS_BASE   6
#define WI_KGS_BASE  7

#define MSR_IA32_PAT             0x277u
#define MSR_IA32_FS_BASE         0xC0000100u
#define MSR_IA32_GS_BASE         0xC0000101u
#define MSR_IA32_KERNEL_GS_BASE  0xC0000102u
#define CR4_OSXSAVE              (1ull << 18)

/* The wake trampoline blob, linked in as a flat binary (drivers/acpi/meson.build). */
extern const unsigned char _binary_build_wake_bin_start[];
extern const unsigned char _binary_build_wake_bin_end[];

/* The suspend stub and the two C callbacks it calls (suspend.asm). */
extern int acpi_suspend_lowlevel(void);
int acpi_enter_sleep(void);
void acpi_resume_finish(void);

static int s3_entered;   /* set when AcpiEnterSleepState() returned (no sleep) */
static int s3_resumed;   /* set by acpi_resume_finish() after a real wake      */

static inline uint64_t msr_read(uint32_t msr)
{
    uint32_t lo, hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t xcr0_read(void)
{
    uint32_t lo, hi;
    __asm__ __volatile__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    return ((uint64_t)hi << 32) | lo;
}

int acpi_s3_supported(void)
{
    return (pm_ready && (s_state_mask & (1u << ACPI_STATE_S3))) ? 1 : 0;
}

/* Copy the trampoline to its low page and record the machine state the sleep
 * resets.  The stack pointer and resume RIP are filled in by suspend.asm. */
static void wake_stage(void)
{
    uint32_t len = (uint32_t)(_binary_build_wake_bin_end - _binary_build_wake_bin_start);
    uint32_t cr4;

    if (len > 4096u)
        len = 4096u;
    memcpy((void *)(uintptr_t)WAKE_TRAMP_PHYS, _binary_build_wake_bin_start, len);

    cr4 = (uint32_t)cpu_read_cr4();
    WAKE_INFO[WI_CR0]      = cpu_read_cr0();
    WAKE_INFO[WI_CR3]      = cpu_read_cr3();
    WAKE_INFO[WI_CR4]      = cr4;
    WAKE_INFO[WI_PAT]      = msr_read(MSR_IA32_PAT);
    WAKE_INFO[WI_XCR0]     = (cr4 & CR4_OSXSAVE) ? xcr0_read() : 0;
    WAKE_INFO[WI_FS_BASE]  = msr_read(MSR_IA32_FS_BASE);
    WAKE_INFO[WI_GS_BASE]  = msr_read(MSR_IA32_GS_BASE);
    WAKE_INFO[WI_KGS_BASE] = msr_read(MSR_IA32_KERNEL_GS_BASE);
}

/* Called from acpi_suspend_lowlevel() with interrupts already off.  Falling
 * through AcpiEnterSleepState() means the machine never slept. */
int acpi_enter_sleep(void)
{
    /* The last line the console can show before the machine stops: if a
     * suspend "hangs", this is the point it stopped at (S1/S3 keep the console
     * dark until wake). */
    pr_notice("%s: entering S3 (SLP_EN)\n", "power");
    __asm__ __volatile__("cli");
    ACPI_STATUS status = AcpiEnterSleepState(ACPI_STATE_S3);
    s3_entered = 1;
    return ACPI_FAILURE(status) ? -1 : 0;
}

/* The wake path: re-establish what the sleep reset, then return to
 * acpi_suspend_lowlevel()'s epilogue.  Interrupts stay off to the end so the
 * LAPIC and timebase are live before the first tick arrives. */
void acpi_resume_finish(void)
{
    s3_resumed = 1;

    /* The GDT/IDT tables and every MSR survive in RAM; only the CPU's
     * registers were reset.  Reload the descriptor tables first — until the
     * IDT is back, a fault (or the console's own code) has nowhere to go. */
    gdt_reload();             /* GDTR, segment registers, TR                   */
    idt_reload();             /* IDTR (the trampoline leaves it zeroed)        */

    pr_notice("%s: resumed from S3\n", "power");

    /* The rest of the CPU-level bring-up boot performs. */
    fpu_global_init();        /* CR0.EM/MP, CR4.OSFXSR/OSXMMEXCPT, fninit      */
    pat_init();               /* IA32_PAT write-combining entry                */
    cpu_syscall_commit();     /* EFER.SCE, STAR/LSTAR/FMASK                    */

    apic_resume();            /* LAPIC + the LAPIC-timer scheduler tick        */
    ktime_resume();           /* resync the PM-timer baseline                  */

    /* ACPI housekeeping: re-enable the runtime GPEs and run _WAK. */
    (void)AcpiLeaveSleepStatePrep(ACPI_STATE_S3);
    (void)AcpiLeaveSleepState(ACPI_STATE_S3);

    pr_notice("%s: machine state restored; interrupts back on\n", "power");
    __asm__ __volatile__("sti");
}

/* Point the firmware at the trampoline and evaluate _PTS, then let the asm
 * stub save the resume context and enter the sleep. */
static int wake_prepare(void)
{
    wake_stage();

    /* The 32-bit waking vector is a real-mode entry point; the 64-bit one is
     * cleared (ACPI 2.0+ prefers the 32-bit vector, and some firmware chokes on
     * the 64-bit form). */
    AcpiSetFirmwareWakingVector(WAKE_TRAMP_PHYS, 0);

    if (ACPI_FAILURE(AcpiEnterSleepStatePrep(ACPI_STATE_S3))) {
        pr_err("%s: _PTS/S3 preparation failed\n", "power");
        return -1;
    }
    pr_notice("%s: wake vector -> 0x%x, _PTS done\n",
              "power", (unsigned)WAKE_TRAMP_PHYS);
    return 0;
}

int acpi_suspend(void)
{
    if (!acpi_s3_supported()) {
        pr_warn("%s: firmware advertises no S3 state\n", "power");
        return -1;
    }

    pr_notice("%s: suspend to RAM (S3)\n", "power");

    /* The sleep must run on the master core: the BSP is the only core that
     * wakes from S3, and only the BSP can park (INIT) the worker cores. */
    smp_migrate_to_master();

    /* Park the worker cores: a core that is executing (or holding a scheduler
     * lock) while the machine sleeps is never coming back cleanly.  A busy
     * worker is evacuated (its work drained to the master) first; if one
     * cannot be parked, the suspend aborts here with nothing left changed. */
    pr_notice("%s: parking worker cores\n", "power");
    if (smp_suspend_workers() != 0) {
        pr_warn("%s: a worker core is busy — refusing to suspend\n", "power");
        return -1;
    }
    pr_notice("%s: all worker cores parked\n", "power");

    if (wake_prepare() != 0) {
        smp_resume_workers();
        return -1;
    }

    s3_entered = 0;
    s3_resumed = 0;
    ktime_suspend();          /* freshen the timebase baseline before the sleep */
    (void)acpi_suspend_lowlevel();

    /* Re-online the parked workers — on a completed resume, and equally when
     * the sleep never happened (a no-op if none were parked). */
    smp_resume_workers();

    if (s3_resumed) {
        pr_notice("%s: S3 resume complete\n", "power");
        return 0;
    }
    if (s3_entered)
        pr_warn("%s: S3 was not entered — firmware ignored SLP_EN\n", "power");
    return -1;
}

int acpi_pm_init(void)
{
    if (!acpi_available()) {
        pr_warn("%s: no ACPI — power paths fall back to port I/O\n", "power");
        return -1;
    }

    pm_ready = 1;
    acpi_sleep_states(&s_state_mask);

    pr_info("%s: PM1a_CNT=0x%x reset-reg=%s sleep=[%s%s%s%s%s]\n",
            "power",
            (unsigned)AcpiGbl_FADT.Pm1aControlBlock,
            (AcpiGbl_FADT.Flags & ACPI_FADT_RESET_REGISTER) ? "yes" : "no",
            (s_state_mask & (1u << 1)) ? "S1 " : "",
            (s_state_mask & (1u << 2)) ? "S2 " : "",
            (s_state_mask & (1u << 3)) ? "S3 " : "",
            (s_state_mask & (1u << 4)) ? "S4 " : "",
            (s_state_mask & (1u << 5)) ? "S5" : "");
    return 0;
}

void acpi_power_off(void)
{
    int prep_ok = 0;

    pr_notice("%s: poweroff (S5)\n", "power");

    if (pm_ready)
        prep_ok = ACPI_SUCCESS(AcpiEnterSleepStatePrep(ACPI_STATE_S5));

    __asm__ volatile ("cli");   /* no scheduler, no IRQs past this point */

    if (prep_ok) {
        (void)AcpiEnterSleepState(ACPI_STATE_S5);
        pr_warn("%s: S5 returned without powering off\n", "power");
    }

    if (pm1_write_direct(ACPI_STATE_S5)) {
        spin_ms(2000);
        pr_warn("%s: direct PM1 write did not power off\n", "power");
    }

    /* QEMU/Bochs convention: SLP_EN|SLP_TYP=0 on the well-known PM1a ports. */
    outw(QEMU_PM1A_CNT,  (uint16_t)PM1_SLP_EN);
    outw(BOCHS_PM1A_CNT, (uint16_t)PM1_SLP_EN);

    spin_ms(2000);
    pr_err("%s: poweroff unavailable — system halted\n", "power");
    cpu_stop();
}

void acpi_reboot(void)
{
    pr_notice("%s: reboot (reset-reg=0x%x val=0x%x)\n",
              "power",
              (unsigned)AcpiGbl_FADT.ResetRegister.Address,
              (unsigned)AcpiGbl_FADT.ResetValue);
    __asm__ volatile ("cli");

    if (pm_ready && ACPI_SUCCESS(AcpiReset())) {
        pr_notice("%s: reset via the ACPI reset register\n", "power");
        spin_ms(2000);
    }

    /* Reset-control register (PIIX4/ICH9): bit1 pulse plus bit2 system reset. */
    outb(0xCF9, 0x06);
    spin_ms(500);
    outb(0xCF9, 0x0E);
    spin_ms(500);

    kbc_reset();
    spin_ms(1000);

    pr_warn("%s: reset fallbacks exhausted — triple fault\n", "power");
    triple_fault();
}

void acpi_halt(void)
{
    pr_notice("%s: halt\n", "power");
    cpu_stop();
}
