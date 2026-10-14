//! Original procedure `0x0040da38` (255 bytes, `0x40da38–0x40db36`).
//! Evidence: `evidence/0040da38_fn_0040da38.md`.

unsafe extern "C" fn default_read(_s: *mut u8, _d: *mut u8, _n: u32) {}
unsafe extern "C" fn default_alloc(_s: *mut u32, _n: i32) {}
unsafe extern "C" fn default_alloc0(_s: *mut u32, _n: u32, _z: u32) {}
unsafe extern "C" fn default_store(_d: *mut u32, _s: u32) {}
unsafe extern "C" fn default_store2(_d: *mut u32, _s: u32) {}
unsafe extern "C" fn default_thunk(_s: *mut u32) -> *mut u8 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_free(_s: *mut u32) {}

/// Reader `0x40cb34(EAX,EDX,ECX)`; all five sites.
///
/// ponytail: hook for out-of-batch `fn_0040cb34`.
pub static mut HOOK_0040CB34: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_read;
/// ponytail: hook for `fn_00404f00`.
pub static mut HOOK_00404F00: unsafe extern "C" fn(*mut u32, i32) = default_alloc;
/// ponytail: hook for `fn_00404c98`.
pub static mut HOOK_00404C98: unsafe extern "C" fn(*mut u32, u32) = default_store;
/// ponytail: hook for `fn_004049c4`.
pub static mut HOOK_004049C4: unsafe extern "C" fn(*mut u32, u32, u32) = default_alloc0;
/// ponytail: hook for `fn_00404718`.
pub static mut HOOK_00404718: unsafe extern "C" fn(*mut u32, u32) = default_store2;
/// ponytail: hook for `thunk 0x4054ac`.
pub static mut HOOK_004054AC: unsafe extern "C" fn(*mut u32) -> *mut u8 = default_thunk;
/// ponytail: hook for `thunk 0x4049bc`.
pub static mut HOOK_004049BC: unsafe extern "C" fn(*mut u32) -> *mut u8 = default_thunk;
/// ponytail: hook for `fn_004046c4`.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u32) = default_free;
/// ponytail: hook for `thunk 0x404c88`.
pub static mut HOOK_00404C88: unsafe extern "C" fn(*mut u32) = default_free;

/// Two-group counted-blob loader + remainder read + cleanup.
/// `param_1` EAX / `param_2` EDX / `param_3` ECX / `param_4,5` stack.
pub unsafe fn fn_0040da38(
    param_1: *mut u8,
    param_2: *mut u32,
    param_3: i32,
    param_4: i32,
    param_5: i32,
) {
    let mut dst = param_2;
    if param_5 > 0 {
        let mut n = param_5;
        loop {
            let mut len: u32 = 0;
            HOOK_0040CB34(param_1, (&mut len as *mut u32) as *mut u8, 4);
            // ponytail: `SAR 1; JNS / ADC 0` — halve rounding toward +inf for odds.
            let mut half = (len as i32) >> 1;
            if half < 0 {
                half += ((len & 1) != 0) as i32;
            }
            let mut s: u32 = 0;
            HOOK_00404F00(&mut s, half);
            if len != 0 {
                let p = HOOK_004054AC(&mut s);
                HOOK_0040CB34(param_1, p, len);
            }
            HOOK_00404C98(dst, s);
            dst = dst.wrapping_byte_add(4);
            n -= 1;
            if n == 0 {
                break;
            }
        }
    }
    if param_4 > 0 {
        let mut n = param_4;
        loop {
            let mut len: u32 = 0;
            HOOK_0040CB34(param_1, (&mut len as *mut u32) as *mut u8, 4);
            let mut s: u32 = 0;
            HOOK_004049C4(&mut s, len, 0);
            if len != 0 {
                let p = HOOK_004049BC(&mut s);
                HOOK_0040CB34(param_1, p, len);
            }
            HOOK_00404718(dst, s);
            dst = dst.wrapping_byte_add(4);
            n -= 1;
            if n == 0 {
                break;
            }
        }
    }
    let tail = (param_3 as u32).wrapping_sub((param_5.wrapping_add(param_4) as u32).wrapping_mul(4));
    HOOK_0040CB34(param_1, dst as *mut u8, tail);
    let mut c: u32 = 0;
    let mut b: u32 = 0;
    HOOK_004046C4(&mut c);
    HOOK_00404C88(&mut b);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static READS: AtomicUsize = AtomicUsize::new(0);
    static STORES: AtomicUsize = AtomicUsize::new(0);
    static FREES: AtomicUsize = AtomicUsize::new(0);
    static LEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn read(_s: *mut u8, d: *mut u8, n: u32) {
        if n == 4 && (d as usize) != 0 {
            // length-word reads only when target is our stack slot; tail read passes dst ptr.
            // Distinguish by recording all; test asserts counts.
        }
        READS.fetch_add(1, Ordering::SeqCst);
        let _ = LEN.load(Ordering::SeqCst);
    }
    unsafe extern "C" fn alloc(s: *mut u32, _n: i32) {
        *s = 0x77;
    }
    unsafe extern "C" fn store(d: *mut u32, _s: u32) {
        STORES.fetch_add(1, Ordering::SeqCst);
        *d = 0x77;
    }
    unsafe extern "C" fn free(_s: *mut u32) {
        FREES.fetch_add(1, Ordering::SeqCst);
    }

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn zero_counts_tail_only() {
        let _lock = LOCK.lock().unwrap();
        unsafe {
            HOOK_0040CB34 = read;
            HOOK_00404F00 = alloc;
            HOOK_00404C98 = store;
            HOOK_004049C4 = super::default_alloc0;
            HOOK_00404718 = super::default_store2;
            HOOK_004046C4 = free;
            HOOK_00404C88 = free;
        }
        READS.store(0, Ordering::SeqCst);
        STORES.store(0, Ordering::SeqCst);
        FREES.store(0, Ordering::SeqCst);
        LEN.store(0, Ordering::SeqCst);
        let mut dst = [0u32; 2];
        unsafe { fn_0040da38(core::ptr::null_mut(), dst.as_mut_ptr(), 16, 0, 0) };
        assert_eq!(READS.load(Ordering::SeqCst), 1); // tail only
        assert_eq!(STORES.load(Ordering::SeqCst), 0);
        assert_eq!(FREES.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn one_zero_len_item() {
        let _lock = LOCK.lock().unwrap();
        unsafe {
            HOOK_0040CB34 = read;
            HOOK_00404F00 = alloc;
            HOOK_00404C98 = store;
            HOOK_004046C4 = free;
            HOOK_00404C88 = free;
        }
        READS.store(0, Ordering::SeqCst);
        STORES.store(0, Ordering::SeqCst);
        FREES.store(0, Ordering::SeqCst);
        let mut dst = [0u32; 2];
        // Length word stays 0 (read hook leaves it) → no inner read, one store + tail.
        unsafe { fn_0040da38(core::ptr::null_mut(), dst.as_mut_ptr(), 8, 0, 1) };
        assert_eq!(READS.load(Ordering::SeqCst), 2); // len + tail
        assert_eq!(STORES.load(Ordering::SeqCst), 1);
        assert_eq!(dst[0], 0x77);
    }
}
