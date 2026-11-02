#ifndef CACT_TEST_STUB_KERNEL_H
#define CACT_TEST_STUB_KERNEL_H

/*
 * Host-build stand-in for Cact/kernel/core/kernel.h, used only by
 * tools/dmi_parse_test.  The real header pulls in the Multiboot2 and memory
 * headers and routes pr_*() through klog; the probe under test needs nothing
 * from it but the fixed-width types and the log macros.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define pr_err(fmt, ...)   printf("[err ] " fmt "\n", ##__VA_ARGS__)
#define pr_warn(fmt, ...)  printf("[warn] " fmt "\n", ##__VA_ARGS__)
#define pr_info(fmt, ...)  printf("[info] " fmt "\n", ##__VA_ARGS__)

#endif
