//! Original procedure `0x0040e280` (104 bytes, `0x0040e280–0x0040e2e7`).
//! Evidence: `evidence/0040e280_fn_0040e280.md`.

unsafe extern "C" fn default_init(_d: *mut u32, _s: u32) {}
unsafe extern "C" fn default_conv(_d: *mut u32, _c: u16) {}
unsafe extern "C" fn default_append(_s: u32, _d: *mut u32, _n: u32) {}
unsafe extern "C" fn default_free(_s: *mut u32) {}

/// ponytail: hook for `fn_00404c98`.
pub static mut HOOK_00404C98: unsafe extern "C" fn(*mut u32, u32) = default_init;
/// ponytail: hook for `fn_00404e04`.
pub static mut HOOK_00404E04: unsafe extern "C" fn(*mut u32, u16) = default_conv;
/// ponytail: hook for `fn_0040532c`.
pub static mut HOOK_0040532C: unsafe extern "C" fn(u32, *mut u32, u32) = default_append;
/// ponytail: hook for `thunk 0x00404c88`.
pub static mut HOOK_00404C88: unsafe extern "C" fn(*mut u32) = default_free;

/// Char table `DAT_00412a9c` (word-indexed by 5-bit chunks).
///
/// ponytail: address-named static; contents unproven, default zeros.
pub static mut DAT_00412A9C: [u16; 32] = [0; 32];

/// Encode 25 bits (5×5-bit chunks, LSB first) into list.
/// `param_1` EAX / `param_2` EDX per `__register` observation.
pub unsafe fn fn_0040e280(mut param_1: u32, param_2: *mut u32) {
    HOOK_00404C98(param_2, 0);
    let mut n = 5;
    loop {
        // ponytail: `AND 0x1f` + word load + `SHR 5` order matches.
        let w = DAT_00412A9C[(param_1 & 0x1f) as usize];
        let mut s: u32 = 0;
        HOOK_00404E04(&mut s, w);
        HOOK_0040532C(s, param_2, 1);
        param_1 >>= 5;
        n -= 1;
        if n == 0 {
            break;
        }
    }
    let mut s: u32 = 0;
    HOOK_00404C88(&mut s);
    // ponytail: SEH frame (`0x0040e2e8/ef`) not modeled — test-platform init detail.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static INITS: AtomicUsize = AtomicUsize::new(0);
    static CONVS: AtomicUsize = AtomicUsize::new(0);
    static APPENDS: AtomicUsize = AtomicUsize::new(0);
    static FREES: AtomicUsize = AtomicUsize::new(0);
    static WORDS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn init(_d: *mut u32, _s: u32) {
        INITS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn conv(_d: *mut u32, c: u16) {
        CONVS.fetch_add(1, Ordering::SeqCst);
        WORDS.store(c as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn append(_s: u32, _d: *mut u32, n: u32) {
        assert_eq!(n, 1);
        APPENDS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn free(_s: *mut u32) {
        FREES.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn five_chunks_lsb_first() {
        unsafe {
            HOOK_00404C98 = init;
            HOOK_00404E04 = conv;
            HOOK_0040532C = append;
            HOOK_00404C88 = free;
            for (i, w) in DAT_00412A9C.iter_mut().enumerate() {
                *w = 0x100 + i as u16;
            }
        }
        INITS.store(0, Ordering::SeqCst);
        CONVS.store(0, Ordering::SeqCst);
        APPENDS.store(0, Ordering::SeqCst);
        FREES.store(0, Ordering::SeqCst);
        let mut dst = 0u32;
        unsafe { fn_0040e280(0b1_00010_00011_00100_00101, &mut dst) };
        assert_eq!(INITS.load(Ordering::SeqCst), 1);
        assert_eq!(CONVS.load(Ordering::SeqCst), 5);
        assert_eq!(APPENDS.load(Ordering::SeqCst), 5);
        assert_eq!(FREES.load(Ordering::SeqCst), 1);
        // Last chunk = top 5 bits = 0b1 → word 0x101.
        assert_eq!(WORDS.load(Ordering::SeqCst), 0x101);
    }
}
