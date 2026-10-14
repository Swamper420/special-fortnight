//! Original procedure `0x00404c1c` (11 bytes, `0x00404c1c–0x00404c20` + `0x00404c24–0x00404c29`).
//! Evidence: `evidence/00404c1c_fn_00404c1c.md`.

/// Cell observed as `DAT_00404c22`, address-taken on null lane. First 2
/// image bytes are `00 00`; caller `0x00404af0` uses the result as a
/// wide-string pointer.
///
/// ponytail: absolute-address cell as mutable static, upgrade to real
/// image-relative import once data layout proven. `u16` ceiling from
/// the observed `00 00` + wide-string use; widen once a longer deref
/// width is proven.
pub static mut CELL_00404C22: u16 = 0;

/// `if param_1 { param_1 } else { &DAT_00404c22 }`. `param_1` arrives
/// in EAX, result leaves in EAX per Ghidra `__register` observation.
pub unsafe fn fn_00404c1c(param_1: *const u8) -> *const u8 {
    if !param_1.is_null() {
        param_1
    } else {
        core::ptr::addr_of!(CELL_00404C22) as *const u8
    }
}

#[cfg(test)]
mod tests {
    use super::{CELL_00404C22, fn_00404c1c};

    #[test]
    fn passthrough_and_default_lanes() {
        let arg = 0x1234 as *const u8;
        assert_eq!(unsafe { fn_00404c1c(arg) }, arg);
        assert_eq!(
            unsafe { fn_00404c1c(core::ptr::null()) },
            core::ptr::addr_of!(CELL_00404C22) as *const u8
        );
    }
}
