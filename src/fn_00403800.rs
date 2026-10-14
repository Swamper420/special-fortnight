//! Original procedure `0x00403800` (10 bytes, `0x403800–0x403809`).
//! Evidence: `evidence/00403800_fn_00403800.md`.

/// `FNINIT; WAIT; FLDCW [0x41201c]; RET`. No args, void.
///
/// ponytail: `asm!` is the native `fninit`/`wait`/`fldcw` equivalent (no
/// stable intrinsic, mirrors sibling `fn_00403100`); cell read through
/// existing `crate::fn_00403100::CELL_0041201c`, no duplicate cell.
/// FPU effect gated to x86/x86_64.
pub unsafe fn fn_00403800() {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    core::arch::asm!(
        "fninit",
        "wait",
        "fldcw word ptr [{0}]",
        in(reg) core::ptr::addr_of!(crate::fn_00403100::CELL_0041201c),
        options(nostack),
    );
}

#[cfg(test)]
mod tests {
    use super::fn_00403800;

    #[test]
    fn init_then_loads_x87_control_word() {
        let _guard = crate::fn_00403100::TEST_LOCK.lock().unwrap();
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            let mut saved: u16 = 0;
            core::arch::asm!("fstcw word ptr [{0}]", in(reg) &mut saved, options(nostack));
            let saved_cell = crate::fn_00403100::CELL_0041201c;
            crate::fn_00403100::CELL_0041201c = 0x033f;
            fn_00403800();
            let mut got: u16 = 0;
            core::arch::asm!("fstcw word ptr [{0}]", in(reg) &mut got, options(nostack));
            // Reserved bits 6-7 read back as 1; mask them before compare.
            assert_eq!(got | 0x00c0, 0x033f | 0x00c0);
            crate::fn_00403100::CELL_0041201c = saved_cell;
            core::arch::asm!(
                "fnclex",
                "fldcw word ptr [{0}]",
                in(reg) &saved,
                options(nostack),
            );
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        unsafe {
            fn_00403800();
        }
    }
}
