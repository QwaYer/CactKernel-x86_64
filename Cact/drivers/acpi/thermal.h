/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#ifndef CACT_THERMAL_H
#define CACT_THERMAL_H

#include <stdint.h>

/* Hardware temperature sources behind /proc/sensors (thermal.c):
 *
 *  - ACPI thermal zones (_TZ objects) evaluated live via _TMP;
 *  - the Intel digital thermal sensor (IA32_THERM_STATUS), if the CPU
 *    reports one.
 */

/* Collect the ACPI thermal-zone handles from the namespace.  0 when at least
 * one zone was found, -1 otherwise (no ACPI, or no zones). */
int acpi_thermal_probe(void);

/* Number of ACPI thermal zones found by the probe. */
int acpi_thermal_count(void);

/* Read zone @idx's _TMP.  Returns 0 and stores tenths of Celsius, or -1. */
int acpi_thermal_read(int idx, int *celsius_tenths);

/* Intel DTS, sampled per CPU.  The digital thermal sensor MSRs are per logical
 * CPU and readable only locally, so thermal_cpu_sample() — called from the
 * timer tick on every core — reads the calling CPU's sensor and remembers it;
 * intel_dts_cpu() returns that CPU's last sample.  intel_dts_available()
 * reports whether the family/CPU supports it at all. */
void thermal_cpu_sample(int cpu);
int  intel_dts_available(void);
int  intel_dts_cpu(int cpu, int *celsius);

#endif
