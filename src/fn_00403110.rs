//! Original procedure `0x00403110` (7 bytes, `0x403110–0x403116`).
//! Evidence: `evidence/00403110_fn_00403110.md`.

/// `PUSH 0; FNSTCW [ESP]; POP EAX`. No params, x87 control word
/// returns in AX per Ghidra `__register` observation (high word of
/// EAX is the pushed 0).
///
/// ponytail: `asm!` is the native `fnstcw` equivalent (no stable
/// intrinsic, mirrors sibling `fn_00403100`); direct word store
/// replaces the push/pop slot, same observable result. Non-x86
/// returns 0.
pub unsafe fn fn_00403110() -> u16 {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let mut cw: u16 = 0;
        core::arch::asm!(
            "fnstcw word ptr [{0}]",
            in(reg) &mut cw,
            options(nostack),
        );
        cw
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::fn_00403110;

    #[test]
    fn reads_stable_fpu_control_word() {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            let a = fn_00403110();
            let b = fn_00403110();
            assert_eq!(a, b);
            let mut direct: u16 = 0;
            core::arch::asm!(
                "fstcw word ptr [{0}]",
                in(reg) &mut direct,
                options(nostack)
            );
            assert_eq!(a, direct);
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        unsafe {
            assert_eq!(fn_00403110(), 0);
        }
    }
}
