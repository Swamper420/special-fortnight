//! Original procedure `0x00403100` (15 bytes, `0x403100–0x40310e`).
//! Evidence: `evidence/00403100_fn_00403100.md`.

/// Word cell observed as `word ptr [0x0041201c]`, stored from AX then
/// loaded into the x87 control word.
///
/// ponytail: absolute-address cell as module static, upgrade to real
/// image-relative import once data layout proven.
pub static mut CELL_0041201c: u16 = 0;

/// `DAT_0041201c = AX; FNCLEX; FLDCW [DAT_0041201c]`.
/// Param arrives in AX per Ghidra `__register` observation.
///
/// ponytail: `asm!` is the native `fnclex`/`fldcw` equivalent (no stable
/// intrinsic); cell store always runs, FPU effect gated to x86/x86_64.
pub unsafe fn fn_00403100(param_1: u16) {
    CELL_0041201c = param_1;
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    core::arch::asm!(
        "fnclex",
        "fldcw word ptr [{0}]",
        in(reg) core::ptr::addr_of!(CELL_0041201c),
        options(nostack),
    );
}

/// Test-only serialization for tests sharing CELL_0041201c / host x87 CW.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::{CELL_0041201c, TEST_LOCK, fn_00403100};

    #[test]
    fn stores_word_and_loads_x87_control_word() {
        let _guard = TEST_LOCK.lock().unwrap();
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            let mut saved: u16 = 0;
            core::arch::asm!("fstcw word ptr [{0}]", in(reg) &mut saved, options(nostack));
            fn_00403100(0x033f);
            assert_eq!(CELL_0041201c, 0x033f);
            let mut got: u16 = 0;
            core::arch::asm!("fstcw word ptr [{0}]", in(reg) &mut got, options(nostack));
            // Reserved bits 6-7 read back as 1; mask them before compare.
            assert_eq!(got | 0x00c0, 0x033f | 0x00c0);
            CELL_0041201c = saved;
            core::arch::asm!(
                "fnclex",
                "fldcw word ptr [{0}]",
                in(reg) core::ptr::addr_of!(CELL_0041201c),
                options(nostack),
            );
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        unsafe {
            fn_00403100(0x033f);
            assert_eq!(CELL_0041201c, 0x033f);
        }
    }
}
