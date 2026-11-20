/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 CactOS Project */

#include "pci_driver.h"
#include "pci_loader.h"
#include "pcidev.h"
#include "kernel.h"
#include "klib.h"

#define PCI_PROC_MAX 32768

int pci_proc_read(uint64_t off, uint32_t size, char *buf)
{
    extern pci_driver_t *pcidev_driver_list;
    extern uint32_t      pcidev_driver_count;

    static char tmp[PCI_PROC_MAX];

    uint32_t nreg = pcidev_driver_count;

    int p = 0;
    p = buf_append(tmp, p, PCI_PROC_MAX, "# /proc/pci - PCI overview\n");
    p = buf_append(tmp, p, PCI_PROC_MAX, "# A: structs from pci_register_driver()  ");
    p = buf_append(tmp, p, PCI_PROC_MAX, "B: every function found by pci_enumerate()\n\n");

    p = buf_append(tmp, p, PCI_PROC_MAX, "# --- A. pci_register_driver() ---\n");
    p = buf_append(tmp, p, PCI_PROC_MAX, "# Drivers registered: ");
    p = buf_append_int(tmp, p, PCI_PROC_MAX, (int)nreg);
    p = buf_append(tmp, p, PCI_PROC_MAX, "  (0xFFFF = PCI_ANY_ID)\n");
    p = buf_append(tmp, p, PCI_PROC_MAX, "# \"probe bound\" = entry point ready ");
    p = buf_append(tmp, p, PCI_PROC_MAX, "(built-in or module loaded)\n\n");

    int idx = 0;
    char hx[16];
    for (pci_driver_t *d = pcidev_driver_list; d; d = d->next) {
        idx++;
        if (p >= PCI_PROC_MAX - 520) {
            pr_debug("%s: /proc/pci driver section truncated (%d drivers)\n",
                     "pci-drv", idx);
            p = buf_append(tmp, p, PCI_PROC_MAX, "\n# ... A truncated ...\n");
            break;
        }

        p = buf_append(tmp, p, PCI_PROC_MAX, "[drv ");
        p = buf_append_int(tmp, p, PCI_PROC_MAX, idx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "] ");
        p = buf_append(tmp, p, PCI_PROC_MAX, d->name);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    vendor_id:       ");
        snprintf(hx, sizeof(hx), "0x%x", (unsigned)((unsigned int)d->vendor_id));
        p = buf_append(tmp, p, PCI_PROC_MAX, hx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    device_id:       ");
        snprintf(hx, sizeof(hx), "0x%x", (unsigned)((unsigned int)d->device_id));
        p = buf_append(tmp, p, PCI_PROC_MAX, hx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    class_code:      ");
        snprintf(hx, sizeof(hx), "0x%x", (unsigned)((unsigned int)d->class_code));
        p = buf_append(tmp, p, PCI_PROC_MAX, hx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    subclass:        ");
        snprintf(hx, sizeof(hx), "0x%x", (unsigned)((unsigned int)d->subclass));
        p = buf_append(tmp, p, PCI_PROC_MAX, hx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    module_path:     ");
        if (d->module_path)
            p = buf_append(tmp, p, PCI_PROC_MAX, (char *)d->module_path);
        else
            p = buf_append(tmp, p, PCI_PROC_MAX, "(none - built-in or no lazy path)");
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    probe bound:     ");
        if (d->probe)
            p = buf_append(tmp, p, PCI_PROC_MAX, "yes\n");
        else
            p = buf_append(tmp, p, PCI_PROC_MAX, "no (lazy load not done yet)\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    kmod unload:     ");
        if (d->flags & PCI_DRV_F_RELOC_MODULE)
            p = buf_append(tmp, p, PCI_PROC_MAX, "yes (sys_module_unload \"");
        else
            p = buf_append(tmp, p, PCI_PROC_MAX, "no (built-in, not ET_REL)\n");
        if (d->flags & PCI_DRV_F_RELOC_MODULE) {
            p = buf_append(tmp, p, PCI_PROC_MAX, d->name);
            p = buf_append(tmp, p, PCI_PROC_MAX, "\")\n");
        }

        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");
    }

    p = buf_append(tmp, p, PCI_PROC_MAX, "# --- B. pci_enumerate() - PCI functions ---\n");
    p = buf_append(tmp, p, PCI_PROC_MAX, "# Devices in list: ");
    p = buf_append_int(tmp, p, PCI_PROC_MAX, (int)pci_device_count);
    p = buf_append(tmp, p, PCI_PROC_MAX, "\n\n");

    int bidx = 0;
    for (pci_device_t *dv = pci_device_list; dv; dv = dv->next) {
        bidx++;
        if (p >= PCI_PROC_MAX - 400) {
            pr_debug("%s: /proc/pci device section truncated (%d devices)\n",
                     "pci-drv", bidx);
            p = buf_append(tmp, p, PCI_PROC_MAX, "\n# ... B truncated ...\n");
            break;
        }

        p = buf_append(tmp, p, PCI_PROC_MAX, "[pci ");
        p = buf_append_int(tmp, p, PCI_PROC_MAX, bidx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "] ");
        p = buf_append(tmp, p, PCI_PROC_MAX, "bus ");
        p = buf_append_int(tmp, p, PCI_PROC_MAX, (int)dv->bus);
        p = buf_append(tmp, p, PCI_PROC_MAX, " dev ");
        p = buf_append_int(tmp, p, PCI_PROC_MAX, (int)dv->dev);
        p = buf_append(tmp, p, PCI_PROC_MAX, " fn ");
        p = buf_append_int(tmp, p, PCI_PROC_MAX, (int)dv->fn);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    vendor_id:       ");
        snprintf(hx, sizeof(hx), "0x%x", (unsigned)((unsigned int)dv->vendor_id));
        p = buf_append(tmp, p, PCI_PROC_MAX, hx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    device_id:       ");
        snprintf(hx, sizeof(hx), "0x%x", (unsigned)((unsigned int)dv->device_id));
        p = buf_append(tmp, p, PCI_PROC_MAX, hx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    class_code:      ");
        snprintf(hx, sizeof(hx), "0x%x", (unsigned)((unsigned int)dv->class_code));
        p = buf_append(tmp, p, PCI_PROC_MAX, hx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    subclass:        ");
        snprintf(hx, sizeof(hx), "0x%x", (unsigned)((unsigned int)dv->subclass));
        p = buf_append(tmp, p, PCI_PROC_MAX, hx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    prog_if:         ");
        snprintf(hx, sizeof(hx), "0x%x", (unsigned)((unsigned int)dv->prog_if));
        p = buf_append(tmp, p, PCI_PROC_MAX, hx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    revision:        ");
        snprintf(hx, sizeof(hx), "0x%x", (unsigned)((unsigned int)dv->revision));
        p = buf_append(tmp, p, PCI_PROC_MAX, hx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    header_type:     ");
        snprintf(hx, sizeof(hx), "0x%x", (unsigned)((unsigned int)dv->header_type));
        p = buf_append(tmp, p, PCI_PROC_MAX, hx);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    irq_line:        ");
        p = buf_append_int(tmp, p, PCI_PROC_MAX, (int)dv->irq_line);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n");

        p = buf_append(tmp, p, PCI_PROC_MAX, "    irq_pin:         ");
        p = buf_append_int(tmp, p, PCI_PROC_MAX, (int)dv->irq_pin);
        p = buf_append(tmp, p, PCI_PROC_MAX, "\n\n");
    }

    int total = 0;
    while (tmp[total] && total < PCI_PROC_MAX - 1) total++;

    if (off >= (uint64_t)total) return 0;
    uint32_t avail = (uint32_t)((uint64_t)total - off);
    if (size > avail) size = avail;
    memcpy(buf, tmp + off, size);
    return (int)size;
}
