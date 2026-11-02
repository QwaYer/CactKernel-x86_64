#ifndef CACT_TEST_STUB_MEMORY_H
#define CACT_TEST_STUB_MEMORY_H

/*
 * Host-build stand-in for Cact/kernel/memory/memory.h, pulled in by the *real*
 * Cact/drivers/acpi/cact_acpi.h.  Only the two symbols that header uses are
 * provided; keeping the real cact_acpi.h (rather than copying its prototypes)
 * is what makes the harness notice if the temp-map API changes.
 */

#include <stdint.h>

#define PAGE_SIZE 4096u
#define KERNEL_MMIO_WINDOW_SIZE (256u * PAGE_SIZE)

uint32_t cact_mmio_window_base(void);

#endif
