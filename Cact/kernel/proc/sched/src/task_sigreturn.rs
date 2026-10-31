//! sigreturn trampoline installation: a per-process user page that issues the
//! `SYS_SIGRETURN` syscall after a signal handler returns.

use crate::ffi::{self, PAGE_PRESENT, PAGE_RW, PAGE_SIZE, PAGE_USER};
use crate::task::TaskStruct;

/// # Safety
///
/// `t` must be null or a live task whose `page_directory` is a valid page directory.
#[no_mangle]
pub unsafe extern "C" fn task_setup_sigreturn(t: *mut TaskStruct) {
    if t.is_null() {
        return;
    }
    // SAFETY: `t` is a live task (non-null checked above; see # Safety), so reading its
    // `page_directory` field is in bounds.
    let pd = unsafe { (*t).page_directory };
    // SAFETY: as above, for the `proc` field.
    let proc = unsafe { (*t).proc };
    if pd.is_null() || proc.is_null() {
        return;
    }
    map_sigreturn_trampoline_on_pd(t, pd);
}

pub(crate) fn map_sigreturn_trampoline_on_pd(t: *mut TaskStruct, pd: *mut u64) {
    if t.is_null() || pd.is_null() {
        return;
    }

    let phys: *mut u8 = cact_mm::kalloc();
    if phys.is_null() {
        return;
    }
    // SAFETY: `phys` points at a freshly allocated page of exactly `PAGE_SIZE` bytes with no
    // other live reference, so a mutable slice over it is valid and exclusive.
    let page = unsafe { core::slice::from_raw_parts_mut(phys, PAGE_SIZE as usize) };

    page.fill(0);
    // SAFETY: `sys_sigreturn_num` is a kernel global holding the statically assigned syscall
    // number; reading it has no preconditions.
    let sigret_num: u32 = unsafe { ffi::sys_sigreturn_num };

    let tramp_vaddr: u64 = 0xBEFFF000;
    // sub rsp, 8          — undo the `ret` that popped ret_addr, so sigreturn
    //                       reads the frame from its base again.
    page[0] = 0x48;
    page[1] = 0x83;
    page[2] = 0xEC;
    page[3] = 0x08;
    // mov eax, SYS_SIGRETURN   (B8 imm32; the write to eax zero-extends into rax)
    page[4] = 0xB8;
    page[5] = (sigret_num & 0xFF) as u8;
    page[6] = ((sigret_num >> 8) & 0xFF) as u8;
    page[7] = ((sigret_num >> 16) & 0xFF) as u8;
    page[8] = ((sigret_num >> 24) & 0xFF) as u8;
    // syscall — long mode's only fast-syscall instruction (SYSENTER is gone);
    // the CPU writes the return RIP into rcx and the user RFLAGS into r11, and
    // the entry grabs both.  No other register setup is needed.
    // Layout: sub(4) + mov eax(5) + syscall(2) + hlt(1) = 12
    page[9]  = 0x0F;
    page[10] = 0x05;
    page[11] = 0xF4;         // hlt (return label — never reached)

    // SAFETY: `t` is a live task (non-null checked at entry), so reading `is_kernel` is in bounds.
    let is_kernel = unsafe { (*t).is_kernel };
    // SAFETY: as above, reading the `proc` field.
    let t_proc = unsafe { (*t).proc };

    let vmm_flags = if is_kernel != 0 {
        PAGE_PRESENT | PAGE_RW
    } else {
        PAGE_PRESENT | PAGE_RW | PAGE_USER
    };
    // SAFETY: `pd` is a valid page directory (checked at entry) and `phys` is a freshly
    // allocated page (a direct-map VA, translated here because the page-table entry takes a
    // physical address), so mapping it at `tramp_vaddr` is the documented operation.
    unsafe {
        cact_mm::vmm_map(pd, tramp_vaddr, cact_mm::vmm_v2p(phys), vmm_flags as i32)
    };

    if !t_proc.is_null() {
        // SAFETY: `t_proc` is the task's live `ProcMeta` (non-null checked here), so storing the
        // trampoline address into it is in bounds.  The address is a fixed low user VA, so it
        // fits the field's 32-bit width.
        unsafe { (*t_proc).sigreturn_trampoline = tramp_vaddr as u32 };
    }
}
