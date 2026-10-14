//! Original procedure `0x0040cee8` (129 bytes, `0x0040cee8–0x0040cf68`).
//! Evidence: `evidence/0040cee8_fn_0040cee8.md`.

unsafe extern "C" fn default_decode(
    _s: *mut u8,
    _b: *mut usize,
    _p2: usize,
    _o: *mut u32,
    _n: u32,
) -> i32 {
    0
}

/// `0x0040ce24` setup: direct intra-cluster call
/// (rewired; signatures verified `fn(*mut u8)`).

/// `0x0040d33c` decode `(state,&block,p2,&out,p3)->i32`.
///
/// ponytail: hook standing in for unreconstructed callee.
pub static mut HOOK_0040D33C: unsafe extern "C" fn(*mut u8, *mut usize, usize, *mut u32, u32) -> i32 =
    default_decode;

/// `0x0040cc3c` reporter (codes 5/6): direct intra-cluster call
/// (rewired; signatures verified `fn(u32)`).

/// `0x0040cd3c` reporter `(str,&code,0)`: direct intra-cluster call
/// (rewired; signatures verified `fn(*mut u16, u32, u32)`).

/// Format string Grave accent`0x0040cf78` (`LzmaDecode failed (%d)`).
///
/// ponytail: absolute-address cell as own-module static, unify in
/// `data.rs` once data layout proven.
pub static mut DAT_0040CF78: usize = 0;

/// Ready-gate → decode → `r==0` ok / `1`→`(5)` / else→`cd3c` → shortfall→`(6)`.
pub unsafe fn fn_0040cee8(param_1: *mut u8, param_2: usize, param_3: u32) {
    if core::ptr::read_unaligned(param_1.wrapping_byte_add(0x11) as *const u8) == 0 {
        crate::fn_0040ce24::fn_0040ce24(param_1);
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
            crate::fn_0040cc3c::fn_0040cc3c(5);
        } else {
            let code: u32 = r as u32;
            crate::fn_0040cd3c::fn_0040cd3c(DAT_0040CF78 as *mut u16, code, 0);
        }
    }
    if out != param_3 {
        crate::fn_0040cc3c::fn_0040cc3c(6);
    }
}

#[cfg(test)]
mod tests {
    use super::{DAT_0040CF78, HOOK_0040D33C, fn_0040cee8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RET: AtomicUsize = AtomicUsize::new(0);
    static OUT: AtomicUsize = AtomicUsize::new(0);
    static FAIL: AtomicUsize = AtomicUsize::new(0);
    static REP: AtomicUsize = AtomicUsize::new(0);
    static EMIT24: AtomicUsize = AtomicUsize::new(0);
    static SZ24: AtomicUsize = AtomicUsize::new(0);
    static OFF24: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn decode(_s: *mut u8, _b: *mut usize, _p: usize, o: *mut u32, _n: u32) -> i32 {
        *o = OUT.load(Ordering::SeqCst) as u32;
        RET.load(Ordering::SeqCst) as i32
    }
    // Fail codes observed through the real `fn_0040cc3c`.
    unsafe extern "C" fn fmt_fail(
        _p1: usize,
        _p2: u8,
        _p3: *const u16,
        _p4: u32,
        blk: *mut u8,
    ) -> u32 {
        core::ptr::read_unaligned(blk as *const u32)
    }
    unsafe extern "C" fn die_fail(c: u32) {
        FAIL.store(c as usize, Ordering::SeqCst);
    }
    // Reports observed through the real `fn_0040cd3c`'s convert hook.
    unsafe extern "C" fn convert_cap(_a: *mut u16, b: u32, _c: u32, d: *mut u32) {
        REP.store(b as usize, Ordering::SeqCst);
        *d = b;
    }
    // Benign tail for the real `fn_0040ccdc` reached via `cd3c`.
    unsafe extern "C" fn fmt_nop(
        _a: usize,
        _b: u8,
        _c: *const u16,
        _d: u32,
        _blk: *mut u8,
    ) -> u32 {
        0
    }
    unsafe extern "C" fn die_nop(_c: u32) {}
    // Setup observed through the real `fn_0040ce24`'s parse/emit hooks.
    unsafe extern "C" fn read5(_a: u32, _b: *mut u8, _c: u32) -> i32 {
        5
    }
    unsafe extern "C" fn parse24(
        _s: *mut u8,
        _n: u32,
        _h: *const u8,
        o1: *mut u32,
        o2: *mut i32,
        _c: u32,
    ) -> i32 {
        *o1 = SZ24.load(Ordering::SeqCst) as u32;
        *o2 = OFF24.load(Ordering::SeqCst) as i32;
        0
    }
    unsafe extern "C" fn emit24(_s: *mut u8, _d: usize, _o: usize) {
        EMIT24.fetch_add(1, Ordering::SeqCst);
    }

    fn rec(flag: u8) -> [u8; 0x20] {
        let mut r = [0u8; 0x20];
        r[0x11] = flag;
        r
    }

    // Full-size record driving the real `fn_0040ce24` setup lane:
    // short-read-free, parse-ok, equal-size (no realloc), emit counted.
    fn setup_rec() -> [u8; 0x80] {
        let mut r = [0u8; 0x80];
        let base = r.as_mut_ptr();
        unsafe {
            // ponytail: `+8` (8 B indirect word on host) overlaps `+0xc`;
            // write the dword first so the indirect word stays intact
            // (stub ignores the arg lane).
            core::ptr::write_unaligned(base.wrapping_byte_add(0xc) as *mut u32, 0);
            core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut usize, read5 as usize);
            core::ptr::write_unaligned(base.wrapping_byte_add(0x64) as *mut u32, 0x7000);
            core::ptr::write_unaligned(base.wrapping_byte_add(0x68) as *mut u32, 0x14);
        }
        SZ24.store(0x10, Ordering::SeqCst);
        OFF24.store(0x4, Ordering::SeqCst);
        r
    }

    #[test]
    fn decode_lanes() {
        unsafe {
            HOOK_0040D33C = decode;
            crate::fn_0040cc3c::HOOK_00409860 = fmt_fail;
            crate::fn_0040cc3c::HOOK_00403F88 = die_fail;
            crate::fn_0040cd3c::HOOK_004082D4 = convert_cap;
            crate::fn_0040ccdc::HOOK_00409860 = fmt_nop;
            crate::fn_0040ccdc::HOOK_00403F88 = die_nop;
            crate::fn_0040ce24::HOOK_0040D9D8 = parse24;
            crate::fn_0040ce24::HOOK_0040DA28 = emit24;
            DAT_0040CF78 = 0xeee;
        }
        // Ready lane: no setup, r==0, sizes match → no report.
        EMIT24.store(0, Ordering::SeqCst);
        RET.store(0, Ordering::SeqCst);
        OUT.store(9, Ordering::SeqCst);
        FAIL.store(0, Ordering::SeqCst);
        let mut r = rec(1);
        unsafe { fn_0040cee8(r.as_mut_ptr(), 0x11, 9) };
        assert_eq!(EMIT24.load(Ordering::SeqCst), 0);
        assert_eq!(FAIL.load(Ordering::SeqCst), 0);
        // Setup lane: flag clear runs the real `ce24` (emit once,
        // ready flag set), then clean decode.
        EMIT24.store(0, Ordering::SeqCst);
        RET.store(0, Ordering::SeqCst);
        OUT.store(9, Ordering::SeqCst);
        FAIL.store(0, Ordering::SeqCst);
        let mut r = setup_rec();
        unsafe { fn_0040cee8(r.as_mut_ptr(), 0x11, 9) };
        assert_eq!(EMIT24.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { core::ptr::read_unaligned(r.as_ptr().wrapping_add(0x11)) }, 1);
        assert_eq!(FAIL.load(Ordering::SeqCst), 0);
        // r==1 → (5), then shortfall overwrites with (6).
        RET.store(1, Ordering::SeqCst);
        OUT.store(3, Ordering::SeqCst);
        let mut r = rec(1);
        unsafe { fn_0040cee8(r.as_mut_ptr(), 0x11, 9) };
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
