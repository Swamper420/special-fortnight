//! Original procedure `0x0040df44` (28 bytes, `0x0040df44–0x0040df5f`).
//! Evidence: `evidence/0040df44_fn_0040df44.md`.

unsafe extern "C" fn default_init(_d: *mut u32, _s: u32) {}

/// Target `0x00404c98` (`FUN_00404c98`) slot init.
///
/// ponytail: hook standing in for out-of-batch `fn_00404c98`.
pub static mut HOOK_00404C98: unsafe extern "C" fn(*mut u32, u32) = default_init;

/// Reset all `0xdd` slots of `DAT_004181a0` with null second arg.
pub unsafe fn fn_0040df44() {
    // ponytail: `MOV BL,0xdd; DEC BL/JNZ` — exactly 0xdd iterations; `wrapping_` matches wrap.
    let mut slot = crate::fn_0040def0::DAT_004181A0.as_mut_ptr();
    let mut n: u8 = 0xdd;
    loop {
        HOOK_00404C98(slot, 0);
        slot = slot.wrapping_byte_add(4);
        n = n.wrapping_sub(1);
        if n == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00404C98, fn_0040df44};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static BASE: AtomicUsize = AtomicUsize::new(0);
    static LAST: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn init(d: *mut u32, s: u32) {
        assert_eq!(s, 0);
        if HITS.fetch_add(1, Ordering::SeqCst) == 0 {
            BASE.store(d as usize, Ordering::SeqCst);
        }
        LAST.store(d as usize, Ordering::SeqCst);
    }

    #[test]
    fn walks_whole_table() {
        unsafe { HOOK_00404C98 = init };
        HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040df44() };
        assert_eq!(HITS.load(Ordering::SeqCst), 0xdd);
        assert_eq!(
            LAST.load(Ordering::SeqCst).wrapping_sub(BASE.load(Ordering::SeqCst)),
            0xdc * 4
        );
    }
}
