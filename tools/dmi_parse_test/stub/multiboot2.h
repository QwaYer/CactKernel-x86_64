#ifndef CACT_TEST_STUB_MULTIBOOT2_H
#define CACT_TEST_STUB_MULTIBOOT2_H

/* Host-build stand-in for Cact/kernel/core/multiboot2.h, for the one symbol
 * drivers/acpi/efi_config.c reads out of it.  The harness defines and sets it. */

#include <stdint.h>

extern uint64_t mb2_efi_systab;

#endif
