//! Original procedure `0x00404d24` (11 bytes, `0x404d24–0x404d2e`).
//! Evidence: `evidence/00404d24_fn_00404d24.md`.

/// Cell observed as `DAT_004127a8`, address-taken on null lane.
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven. Size unobserved
/// (address load, no deref); single byte ceiling, widen once a dref
/// width is proven.
pub static mut CELL_004127A8: u8 = 0;

/// `if param_1 { param_1 } else { &DAT_004127a8 }`. `param_1` arrives
/// in EAX, result leaves in EAX per Ghidra `__register` observation.
pub unsafe fn fn_00404d24(param_1: *const u8) -> *const u8 {
    if !param_1.is_null() {
        param_1
    } else {
        core::ptr::addr_of!(CELL_004127A8) as *const u8
    }
}

#[cfg(test)]
mod tests {
    use super::{CELL_004127A8, fn_00404d24};

    #[test]
    fn passthrough_and_default_lanes() {
        let arg = 0x1234 as *const u8;
        assert_eq!(unsafe { fn_00404d24(arg) }, arg);
        assert_eq!(
            unsafe { fn_00404d24(core::ptr::null()) },
            core::ptr::addr_of!(CELL_004127A8) as *const u8
        );
    }
}
