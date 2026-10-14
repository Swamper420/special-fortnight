//! Original procedure `0x0040c738` (24 bytes, `0x0040c738–0x0040c74f`).
//! Evidence: `evidence/0040c738_fn_0040c738.md`.

unsafe extern "C" fn default_hook(_seed: u32, _buf: *const u8, _len: i32) -> u32 {
    0
}

/// Target `0x0040c6e4`, called with `(0xffffffff, param_1, param_2)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_0040c6e4` once it exists.
pub static mut HOOK_0040c6e4: unsafe extern "C" fn(u32, *const u8, i32) -> u32 =
    default_hook;

/// `FUN_0040c6e4(-1, buf, len) ^ -1`.
/// Register lanes observed: `param_1` in EAX, `param_2` in EDX.
pub unsafe fn fn_0040c738(param_1: *const u8, param_2: i32) -> u32 {
    HOOK_0040c6e4(0xffffffff, param_1, param_2) ^ 0xffffffff
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040c6e4, fn_0040c738};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SEED: AtomicUsize = AtomicUsize::new(0);
    static BUF: AtomicUsize = AtomicUsize::new(0);
    static LEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn hook(seed: u32, buf: *const u8, len: i32) -> u32 {
        SEED.store(seed as usize, Ordering::SeqCst);
        BUF.store(buf as usize, Ordering::SeqCst);
        LEN.store(len as usize, Ordering::SeqCst);
        0x12345678
    }

    #[test]
    fn seeds_neg_one_and_inverts() {
        let data = *b"abcd";
        unsafe {
            HOOK_0040c6e4 = hook;
            assert_eq!(fn_0040c738(data.as_ptr(), 4), 0x12345678 ^ 0xffffffff);
        }
        assert_eq!(SEED.load(Ordering::SeqCst), 0xffffffff);
        assert_eq!(BUF.load(Ordering::SeqCst), data.as_ptr() as usize);
        assert_eq!(LEN.load(Ordering::SeqCst), 4);
    }
}
