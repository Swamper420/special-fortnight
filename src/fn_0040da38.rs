//! Original procedure `0x0040da38` (255 bytes, `0x0040da38–0x0040db36`).
//! Evidence: `evidence/0040da38_fn_0040da38.md`.

unsafe extern "C" fn default_alloc(_s: *mut u32, _n: i32) {}
unsafe extern "C" fn default_alloc0(_s: *mut u32, _n: u32, _z: u32) {}
unsafe extern "C" fn default_store(_d: *mut u32, _s: u32) {}
unsafe extern "C" fn default_store2(_d: *mut u32, _s: u32) {}
unsafe extern "C" fn default_thunk(_s: *mut u32) -> *mut u8 {
    core::ptr::null_mut()
}
unsafe extern "C" fn default_free(_s: *mut u32) {}

/// Reader `0x0040cb34(EAX,EDX,ECX)`; all five sites: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8, u32)`).
/// `0x00404f00` wide-string ensure `(slot, half)`: direct
/// intra-reconstruction call (rewired; `fn_00404f00` verified
/// `fn(*mut *mut u8, u32)`).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_00404f00(s: *mut u32, n: i32) {
    crate::fn_00404f00::fn_00404f00(s as *mut *mut u8, n as u32)
}
pub static mut HOOK_00404F00: unsafe extern "C" fn(*mut u32, i32) = adapt_00404f00;
/// `0x00404c98` acquire-store `(dst, s)`: direct intra-reconstruction
/// call (rewired; `fn_00404c98` verified `fn(*mut u8, *mut u8)`).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_00404c98(d: *mut u32, s: u32) {
    crate::fn_00404c98::fn_00404c98(d as *mut u8, s as *mut u8)
}
pub static mut HOOK_00404C98: unsafe extern "C" fn(*mut u32, u32) = adapt_00404c98;
/// `0x004049c4` alloc `(slot, len, 0)`: direct intra-reconstruction
/// call (rewired; `fn_004049c4` verified `fn(*mut *mut u8, u32, i32)`).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_004049c4(s: *mut u32, n: u32, z: u32) {
    crate::fn_004049c4::fn_004049c4(s as *mut *mut u8, n, z as i32)
}
pub static mut HOOK_004049C4: unsafe extern "C" fn(*mut u32, u32, u32) = adapt_004049c4;
/// `0x00404718` store `(dst, s)`: direct intra-reconstruction call
/// (rewired; `fn_00404718` verified `fn(*mut usize, *mut u8)`).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_00404718(d: *mut u32, s: u32) {
    crate::fn_00404718::fn_00404718(d as *mut usize, s as *mut u8)
}
pub static mut HOOK_00404718: unsafe extern "C" fn(*mut u32, u32) = adapt_00404718;
/// Thunk `0x004054ac` data-pointer `(slot)`: direct
/// intra-reconstruction call (rewired; `fn_004054ac` verified
/// `fn(*mut u32) -> i32`, pointer as int).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_004054ac(s: *mut u32) -> *mut u8 {
    crate::fn_004054ac::fn_004054ac(s) as *mut u8
}
pub static mut HOOK_004054AC: unsafe extern "C" fn(*mut u32) -> *mut u8 = adapt_004054ac;
/// Thunk `0x004049bc` data-pointer `(slot)`: direct
/// intra-reconstruction call (rewired; `fn_004049bc` verified
/// `fn(*mut u32) -> i32`).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_004049bc(s: *mut u32) -> *mut u8 {
    crate::fn_004049bc::fn_004049bc(s) as *mut u8
}
pub static mut HOOK_004049BC: unsafe extern "C" fn(*mut u32) -> *mut u8 = adapt_004049bc;
/// `0x004046c4` release `(slot)`: direct intra-reconstruction call
/// (rewired; `fn_004046c4` verified `fn(*mut u8) -> *mut u8`, return
/// dropped per assembly).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_004046c4(s: *mut u32) {
    crate::fn_004046c4::fn_004046c4(s as *mut u8);
}
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u32) = adapt_004046c4;
/// Thunk `0x00404c88` release `(slot)`: direct intra-reconstruction
/// call (rewired; `fn_00404c88` verified `fn(*mut u32) -> *mut u32`,
/// return dropped per assembly).
// ponytail: adapter, exact parity on i686 only.
unsafe extern "C" fn adapt_00404c88(s: *mut u32) {
    crate::fn_00404c88::fn_00404c88(s);
}
pub static mut HOOK_00404C88: unsafe extern "C" fn(*mut u32) = adapt_00404c88;

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
            crate::fn_0040cb34::fn_0040cb34(param_1, (&mut len as *mut u32) as *mut u8, 4);
            // ponytail: `SAR 1; JNS / ADC 0` — halve rounding toward +inf for odds.
            let mut half = (len as i32) >> 1;
            if half < 0 {
                half += ((len & 1) != 0) as i32;
            }
            let mut s: u32 = 0;
            HOOK_00404F00(&mut s, half);
            if len != 0 {
                let p = HOOK_004054AC(&mut s);
                crate::fn_0040cb34::fn_0040cb34(param_1, p, len);
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
            crate::fn_0040cb34::fn_0040cb34(param_1, (&mut len as *mut u32) as *mut u8, 4);
            let mut s: u32 = 0;
            HOOK_004049C4(&mut s, len, 0);
            if len != 0 {
                let p = HOOK_004049BC(&mut s);
                crate::fn_0040cb34::fn_0040cb34(param_1, p, len);
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
    crate::fn_0040cb34::fn_0040cb34(param_1, dst as *mut u8, tail);
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

    /// Real `fn_0040cb34` drain hook: null slot drains the requested
    /// count (length words stay 0, so no inner read and the error
    /// pair never fires).
    unsafe extern "C" fn drain(_o: *mut u8, _d: *mut u8, _l: u32) -> u32 {
        READS.fetch_add(1, Ordering::SeqCst);
        LEN.load(Ordering::SeqCst) as u32
    }

    /// Null-slot object for the real `fn_0040cb34` (`+4` slot null).
    static mut OBJ_BUF: [u8; 12] = [0; 12];
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
        // Real `fn_0040cb34` behind the reads (its drain hook
        // shared): hold its lock, pin the full-count drain.
        let _cb = crate::fn_0040cb34::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_0040cb34::HOOK_0040cad8 = drain;
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
        LEN.store(16, Ordering::SeqCst);
        let mut dst = [0u32; 2];
        let obj = unsafe { core::ptr::addr_of_mut!(OBJ_BUF) as *mut u8 };
        unsafe { fn_0040da38(obj, dst.as_mut_ptr(), 16, 0, 0) };
        assert_eq!(READS.load(Ordering::SeqCst), 1); // tail only
        assert_eq!(STORES.load(Ordering::SeqCst), 0);
        assert_eq!(FREES.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn one_zero_len_item() {
        let _lock = LOCK.lock().unwrap();
        // Real `fn_0040cb34` behind the reads (its drain hook
        // shared): hold its lock, pin the full-count drain.
        let _cb = crate::fn_0040cb34::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_0040cb34::HOOK_0040cad8 = drain;
            HOOK_00404F00 = alloc;
            HOOK_00404C98 = store;
            HOOK_004046C4 = free;
            HOOK_00404C88 = free;
        }
        READS.store(0, Ordering::SeqCst);
        STORES.store(0, Ordering::SeqCst);
        FREES.store(0, Ordering::SeqCst);
        LEN.store(4, Ordering::SeqCst);
        let mut dst = [0u32; 2];
        // Length word stays 0 (drain leaves it) → no inner read, one store + tail.
        let obj = unsafe { core::ptr::addr_of_mut!(OBJ_BUF) as *mut u8 };
        unsafe { fn_0040da38(obj, dst.as_mut_ptr(), 8, 0, 1) };
        assert_eq!(READS.load(Ordering::SeqCst), 2); // len + tail
        assert_eq!(STORES.load(Ordering::SeqCst), 1);
        assert_eq!(dst[0], 0x77);
    }
}
