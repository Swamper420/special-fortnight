//! Original procedure `0x0040494c` (11 bytes, ranges
//! `0x0040494c–0x00404950` + `0x0040495e–0x00404963`).
//! Evidence: `evidence/0040494c_fn_0040494c.md`.

/// Embedded zero byte at `0x0040495d` (gap padding in `.text`, read-only
/// in original); null input yields its address = empty C string.
/// Sole owner is this function; immutable, so no test lock needed.
///
/// ponytail: module static standing in for image byte, move to `data.rs`
/// only if a shared layout module appears.
pub static DAT_0040495D: u8 = 0;

/// `if p!=0 {p} else {&DAT_0040495d}`. Param arrives in EAX per
/// `__register` observation; returns EAX. Caller `0x00406728` passes result
/// as `LPCSTR` to `GetProcAddress`, hence `*const u8`.
pub unsafe fn fn_0040494c(param_1: *const u8) -> *const u8 {
    if !param_1.is_null() {
        return param_1;
    }
    core::ptr::addr_of!(DAT_0040495D)
}

#[cfg(test)]
mod tests {
    use super::{DAT_0040495D, fn_0040494c};

    #[test]
    fn passthrough_and_empty_default() {
        let buf = [0x41u8; 4];
        let p = buf.as_ptr();
        unsafe {
            assert_eq!(fn_0040494c(p), p);
            let d = fn_0040494c(core::ptr::null());
            assert!(!d.is_null());
            assert_eq!(d, core::ptr::addr_of!(DAT_0040495D));
            assert_eq!(*d, 0);
        }
    }
}
