/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

/*
 * Hardware temperature sources for /proc/sensors.
 *
 * ACPI thermal zones are the portable half: the AML interpreter is already
 * live (acpi_init), so we only walk the namespace for ACPI_TYPE_THERMAL objects
 * and read _TMP on demand — no interpreter work, the same shape as the _CST
 * probe in cstates.c.  We deliberately look objects up by type and never touch
 * _HID, whose repair path faults on some firmware.
 *
 * The Intel DTS is the other half, but reading IA32_THERM_STATUS (0x19C) on a
 * CPU that does not implement it raises #GP, which is fatal in the kernel (no
 * fault-tolerant rdmsr).  It is therefore gated on an Intel vendor and CPUID
 * leaf 6 reporting a digital thermal sensor.
 */
#include "acpi.h"
#include "cact_acpi.h"
#include "thermal.h"
#include "kernel.h"
#include "klib.h"
#include "cpudev.h"
#include "cpu_msr.h"

#define THERMAL_MAX_ZONES 16

static ACPI_HANDLE thermal_zones[THERMAL_MAX_ZONES];
static int         thermal_zone_count = 0;

static ACPI_STATUS thermal_walk_cb(ACPI_HANDLE object, UINT32 level,
                                   void *context, void **return_value)
{
    (void)level; (void)context; (void)return_value;
    if (object && thermal_zone_count < THERMAL_MAX_ZONES)
        thermal_zones[thermal_zone_count++] = object;
    return AE_OK;
}

int acpi_thermal_probe(void)
{
    thermal_zone_count = 0;
    if (!acpi_available())
        return -1;

    ACPI_STATUS status = AcpiWalkNamespace(ACPI_TYPE_THERMAL, ACPI_ROOT_OBJECT,
                                           ACPI_UINT32_MAX, thermal_walk_cb,
                                           NULL, NULL, NULL);
    if (ACPI_FAILURE(status) && status != AE_CTRL_TERMINATE)
        return -1;

    if (thermal_zone_count)
        pr_info("%s: %d ACPI thermal zone(s)\n", "thermal", thermal_zone_count);
    return thermal_zone_count ? 0 : -1;
}

int acpi_thermal_count(void)
{
    return thermal_zone_count;
}

int acpi_thermal_read(int idx, int *celsius_tenths)
{
    if (idx < 0 || idx >= thermal_zone_count)
        return -1;

    ACPI_BUFFER ret;
    ret.Length  = ACPI_ALLOCATE_BUFFER;
    ret.Pointer = NULL;

    ACPI_STATUS status = AcpiEvaluateObject(thermal_zones[idx], "_TMP", NULL, &ret);
    if (ACPI_FAILURE(status) || !ret.Pointer)
        return -1;

    ACPI_OBJECT *o = (ACPI_OBJECT *)ret.Pointer;
    int tk = (o->Type == ACPI_TYPE_INTEGER) ? (int)o->Integer.Value : -1;
    AcpiOsFree(ret.Pointer);
    if (tk < 0)
        return -1;

    *celsius_tenths = tk - 2732;   /* tenths of Kelvin -> tenths of Celsius */
    return 0;
}

/* Intel DTS, sampled per CPU.  -1 = not yet checked, 0 = unsupported, 1 = ok. */
#define THERMAL_MAX_CPUS 64
static int dts_supported = -1;
static int dts_temp[THERMAL_MAX_CPUS];
static int dts_valid[THERMAL_MAX_CPUS];

static int _dts_supported(void)
{
    if (dts_supported >= 0)
        return dts_supported;

    dts_supported = 0;
    if (cpu_vendor() == CPU_VENDOR_INTEL) {
        uint32_t eax, ebx, ecx, edx;
        cact_cpuid(6, 0, &eax, &ebx, &ecx, &edx);
        if (eax & 1u)                 /* CPUID.06H:EAX[0] = digital thermal sensor */
            dts_supported = 1;
    }
    return dts_supported;
}

int intel_dts_available(void)
{
    return _dts_supported();
}

void thermal_cpu_sample(int cpu)
{
    if (cpu < 0 || cpu >= THERMAL_MAX_CPUS)
        return;
    if (!_dts_supported())
        return;

    uint64_t target = cpu_rdmsr(0x1A2);   /* IA32_TEMPERATURE_TARGET (TjMax) */
    uint64_t status = cpu_rdmsr(0x19C);   /* IA32_THERM_STATUS               */
    if (!(status & (1ull << 31)))         /* reading-valid bit clear */
        return;

    int tjmax   = (int)((target >> 16) & 0xFFu);
    int readout = (int)((status >> 16) & 0x7Fu);
    if (tjmax == 0)
        return;

    dts_temp[cpu]  = tjmax - readout;
    dts_valid[cpu] = 1;
}

int intel_dts_cpu(int cpu, int *celsius)
{
    if (cpu < 0 || cpu >= THERMAL_MAX_CPUS || !dts_valid[cpu])
        return -1;
    *celsius = dts_temp[cpu];
    return 0;
}
