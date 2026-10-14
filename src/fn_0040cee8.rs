//! Original procedure `0x0040cee8` (129 bytes, `0x0040cee8–0x0040cf68`).
//! Evidence: `evidence/0040cee8_fn_0040cee8.md`.

unsafe extern "C" fn default_setup(_p: *mut u8) {}
unsafe extern "C" fn default_decode(
    _s: *mut u8,
    _b: *mut usize,
    _p2: usize,
    _o: *mut u32,
    _n: u32,
) -> i32 {
    0
}
unsafe extern "C" fn default_fail(_c: u32) {}
unsafe extern "C" fn default_report(_s: *mut u16, _a: u32, _b: u32) {}

/// `0x0040ce24` setup.
///
/// ponytail: hook standing in for same-batch `fn_0040ce24`.
pub static mut HOOK_0040CE24: unsafe extern "C" fn(*mut u8) = default_setup;

/// `0x0040d33c` decode `(state,&block,p2,&out,p3)->i32`.
///
/// ponytail: hook standing in for unreconstructed callee.
pub static mut HOOK_0040D33C: unsafe extern "C" fn(*mut u8, *mut usize, usize, *mut u32, u32) -> i32 =
    default_decode;

/// `0x0040cc3c` reporter (codes 5/6).
///
/// ponytail: hook standing in for same-batch `fn_0040cc3c`.
pub static mut HOOK_0040CC3C: unsafe extern "C" fn(u32) = default_fail;

/// `0x0040cd3c` reporter `(str,&code,0)`.
///
/// ponytail: hook standing in for same-batch `fn_0040cd3c`.
pub static mut HOOK_0040CD3C: unsafe extern "C" fn(*mut u16, u32, u32) = default_report;

/// Format string Grave accent`0x0040cf78` (`LzmaDecode failed (%d)`).
///
/// ponytail: absolute-address cell as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_0040CF78: usize = 0;

/// Ready-gate → decode → `r==0` ok / `1`→`(5)` / else→`cd3c` → shortfall→`(6)`.
pub unsafe fn fn_0040cee8(param_1: *mut u8, param_2: usize, param_3: u32) {
    if core::ptr::read_unaligned(param_1.wrapping_byte_add(0x11) as *const u8) == 0 {
        HOOK_0040CE24(param_1);
    }
    // ponytail: 2-word block `[0x0040cd94, base]`; label address is a code
    // constant, kept verbatim (target 32-bit wrap = host value here).
    let mut blk = [0x40cd94usize, param_1 as usize];
    let mut out: u32 = 0;
    let r = HOOK_0040D33C(
        param_1.wrapping_byte_add(0x14),
        blk.as_mut_ptr(),
        param_2,
        &mut out,
        param_3,
    );
    if r != 0 {
        if r == 1 {
            HOOK_0040CC3C(5);
        } else {
            let code: u32 = r as u32;
            HOOK_0040CD3C(DAT_0040CF78 as *mut u16, code, 0);
        }
    }
    if out != param_3 {
        HOOK_0040CC3C(6);
    }
}

#[cfg(test)]
mod tests {
    use super::{DAT_0040CF78, HOOK_0040CC3C, HOOK_0040CD3C, HOOK_0040CE24, HOOK_0040D33C, fn_0040cee8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SETUP: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(0);
    static OUT: AtomicUsize = AtomicUsize::new(0);
    static FAIL: AtomicUsize = AtomicUsize::new(0);
    static REP: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn setup(_p: *mut u8) {
        SETUP.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn decode(_s: *mut u8, _b: *mut usize, _p: usize, o: *mut u32, _n: u32) -> i32 {
        *o = OUT.load(Ordering::SeqCst) as u32;
        RET.load(Ordering::SeqCst) as i32
    }
    unsafe extern "C" fn fail(c: u32) {
        FAIL.store(c as usize, Ordering::SeqCst);
    }
    unsafe extern "C" fn report(_s: *mut u16, a: u32, _b: u32) {
        REP.store(a as usize, Ordering::SeqCst);
    }

    fn rec(flag: u8) -> [u8; 0x20] {
        let mut r = [0u8; 0x20];
        r[0x11] = flag;
        r
    }

    #[test]
    fn decode_lanes() {
        unsafe {
            HOOK_0040CE24 = setup;
            HOOK_0040D33C = decode;
            HOOK_0040CC3C = fail;
            HOOK_0040CD3C = report;
            DAT_0040CF78 = 0xeee;
        }
        // Ready lane: no setup, r==0, sizes match → no report.
        SETUP.store(0, Ordering::SeqCst);
        RET.store(0, Ordering::SeqCst);
        OUT.store(9, Ordering::SeqCst);
        FAIL.store(0, Ordering::SeqCst);
        let mut r = rec(1);
        unsafe { fn_0040cee8(r.as_mut_ptr(), 0x11, 9) };
        assert_eq!(SETUP.load(Ordering::SeqCst), 0);
        assert_eq!(FAIL.load(Ordering::SeqCst), 0);
        // r==1 → (5), then shortfall overwrites with (6).
        RET.store(1, Ordering::SeqCst);
        OUT.store(3, Ordering::SeqCst);
        let mut r = rec(0);
        unsafe { fn_0040cee8(r.as_mut_ptr(), 0x11, 9) };
        assert_eq!(SETUP.load(Ordering::SeqCst), 1);
        assert_eq!(FAIL.load(Ordering::SeqCst), 6);
        // r==2 → cd3c(code), sizes match → fail stays 0? set sentinel first.
        FAIL.store(0, Ordering::SeqCst);
        RET.store(2, Ordering::SeqCst);
        OUT.store(9, Ordering::SeqCst);
        REP.store(0, Ordering::SeqCst);
        let mut r = rec(1);
        unsafe { fn_0040cee8(r.as_mut_ptr(), 0x11, 9) };
        assert_eq!(REP.load(Ordering::SeqCst), 2);
        assert_eq!(FAIL.load(Ordering::SeqCst), 0);
    }
}
