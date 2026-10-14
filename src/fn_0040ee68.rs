//! Original procedure `0x0040ee68` (77 bytes, `0x0040ee68–0x0040eeb4`).
//! Evidence: `evidence/0040ee68_fn_0040ee68.md`.

use std::sync::atomic::{AtomicU32, Ordering};

unsafe extern "C" fn default_build(_o: *mut u8, _t: u32) {}
unsafe extern "C" fn default_data(_o: *mut u8) -> u32 {
    0
}
unsafe extern "C" fn default_msg(_h: u32, _t: u32, _c: u32, _ty: u32) -> u32 {
    0
}
unsafe extern "C" fn default_release(_o: *mut u8) {}

/// Target `0x00404cec (obj, help-text at 0x0040eecc)`.
pub static mut HOOK_00404CEC: unsafe extern "C" fn(*mut u8, u32) = default_build;
/// Target `0x00404d24 (obj → text ptr)`.
pub static mut HOOK_00404D24: unsafe extern "C" fn(*mut u8) -> u32 = default_data;
/// Target `0x004068bc MessageBoxW`.
pub static mut HOOK_MESSAGEBOXW: unsafe extern "C" fn(u32, u32, u32, u32) -> u32 = default_msg;
/// Target `0x00404c88` thunk (release obj).
pub static mut HOOK_00404C88: unsafe extern "C" fn(*mut u8) = default_release;

static SEEN_TYPE: AtomicU32 = AtomicU32::new(0);

/// `/HELP` box: builds help string, `MessageBoxW(0, text, L"Setup", 0x10)`,
/// releases string object.
pub unsafe fn fn_0040ee68() {
    let mut obj = [0u8; 8];
    HOOK_00404CEC(obj.as_mut_ptr(), 0x0040eecc);
    let text = HOOK_00404D24(obj.as_mut_ptr());
    // ponytail: hwnd 0, caption 0x004100cc (L"Setup"), MB_ICONHAND 0x10.
    HOOK_MESSAGEBOXW(0, text, 0x004100cc, 0x10);
    HOOK_00404C88(obj.as_mut_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn msg(h: u32, t: u32, c: u32, ty: u32) -> u32 {
        assert_eq!(h, 0);
        assert_eq!(t, 0x1234);
        assert_eq!(c, 0x004100cc);
        SEEN_TYPE.store(ty, Ordering::SeqCst);
        1
    }
    unsafe extern "C" fn data(_o: *mut u8) -> u32 {
        0x1234
    }
    unsafe extern "C" fn nop_build(_o: *mut u8, _t: u32) {}
    unsafe extern "C" fn nop_release(_o: *mut u8) {}

    #[test]
    fn mb_arg_shape() {
        unsafe {
            HOOK_00404CEC = nop_build;
            HOOK_00404D24 = data;
            HOOK_MESSAGEBOXW = msg;
            HOOK_00404C88 = nop_release;
            fn_0040ee68();
            assert_eq!(SEEN_TYPE.load(Ordering::SeqCst), 0x10);
        }
    }
}
