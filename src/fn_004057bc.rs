//! Original procedure `0x004057bc` (276 bytes, `0x004057bc–0x004058cf`).
//! Evidence: `evidence/004057bc_fn_004057bc.md`.

unsafe extern "C" fn default_ab(_a: usize, _b: usize) {}
unsafe extern "C" fn default_a(_a: usize) {}
unsafe extern "C" fn default_abc(_a: usize, _b: usize, _c: *mut u8) {}
unsafe extern "C" fn default_tail(_a: u32) {}

/// `0x00404718` lane (tag `0x0a`), args `(p1, *p2)`, stride 4.
///
/// ponytail: hook standing in for done `fn_00404718`, rewire to real
/// call once cross-module test serialization exists.
pub static mut HOOK_00404718: unsafe extern "C" fn(usize, usize) = default_ab;

/// `0x00404ac8` lane (tag `0x0b`), args `(p1, *p2)`, stride 4.
///
/// ponytail: hook standing in for done `fn_00404ac8`, rewire to real
/// call once cross-module test serialization exists.
pub static mut HOOK_00404AC8: unsafe extern "C" fn(usize, usize) = default_ab;

/// `0x00404c98` lane (tag `0x12`), args `(p1, *p2)`, stride 4.
///
/// ponytail: hook standing in for done `fn_00404c98`, rewire to real
/// call once cross-module test serialization exists.
pub static mut HOOK_00404C98: unsafe extern "C" fn(usize, usize) = default_ab;

/// `0x00405664` lane (tag `0x0c`), arg `(p1)`, stride `0x10`.
///
/// ponytail: hook standing in for sibling `fn_00405664` (same work
/// package), rewire to real call once modules are declared.
pub static mut HOOK_00405664: unsafe extern "C" fn(usize) = default_a;

/// `0x0040567c` lane (tag `0x0e`), args `(p1, p2, p3)`, stride
/// `*(p3 + byte(p3+1) + 2)`.
///
/// ponytail: hook standing in for sibling `fn_0040567c` (same work
/// package), rewire to real call once modules are declared.
pub static mut HOOK_0040567C: unsafe extern "C" fn(usize, usize, *mut u8) =
    default_abc;

/// `0x0040628c` lane (tag `0x0f`), args `(p1, *p2)`, stride 4.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040628c` once it exists.
pub static mut HOOK_0040628C: unsafe extern "C" fn(usize, usize) = default_ab;

/// `0x00405b20` lane (tag `0x11`), args `(p1, *p2, p3)`, stride 4.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00405b20` once it exists.
pub static mut HOOK_00405B20: unsafe extern "C" fn(usize, usize, *mut u8) =
    default_abc;

/// Fail tail `0x00402f60` (`FUN_00402f60`), reached with `AL=2` over the
/// entry `param_1`.
///
/// ponytail: hook standing in for done `fn_00402f60`, rewire to real
/// two-lane call once cross-module test serialization exists.
pub static mut TAIL_00402F60: unsafe extern "C" fn(u32) = default_tail;

/// Tag-dispatched counted filler: one loop per tag over `param_4`
/// items. Params arrive in EAX/EDX/ECX (+stack count) per Ghidra
/// `__register` observation; `RET 0x4` pops the stack count, modeled
/// as a plain by-value `u32`. Bases stay `usize`, dword slots `u32`.
pub unsafe fn fn_004057bc(
    param_1: usize,
    param_2: usize,
    param_3: *mut u8,
    mut param_4: u32,
) {
    let tag: u8 = core::ptr::read_unaligned(param_3 as *const u8);
    if tag == 0x0a {
        let mut a = param_1;
        let mut b = param_2;
        loop {
            let v: usize = core::ptr::read_unaligned(b as *const usize);
            HOOK_00404718(a, v);
            a = a.wrapping_add(4);
            b = b.wrapping_add(4);
            param_4 = param_4.wrapping_sub(1);
            if param_4 == 0 {
                break;
            }
        }
    } else if tag == 0x0b {
        let mut a = param_1;
        let mut b = param_2;
        loop {
            let v: usize = core::ptr::read_unaligned(b as *const usize);
            HOOK_00404AC8(a, v);
            a = a.wrapping_add(4);
            b = b.wrapping_add(4);
            param_4 = param_4.wrapping_sub(1);
            if param_4 == 0 {
                break;
            }
        }
    } else if tag == 0x12 {
        let mut a = param_1;
        let mut b = param_2;
        loop {
            let v: usize = core::ptr::read_unaligned(b as *const usize);
            HOOK_00404C98(a, v);
            a = a.wrapping_add(4);
            b = b.wrapping_add(4);
            param_4 = param_4.wrapping_sub(1);
            if param_4 == 0 {
                break;
            }
        }
    } else if tag == 0x0c {
        let mut a = param_1;
        let mut b = param_2;
        loop {
            HOOK_00405664(a);
            a = a.wrapping_add(0x10);
            b = b.wrapping_add(0x10);
            param_4 = param_4.wrapping_sub(1);
            if param_4 == 0 {
                break;
            }
        }
    } else if tag == 0x0d {
        let u = core::ptr::read_unaligned(param_3.wrapping_byte_add(1) as *const u8)
            as usize;
        let f = (param_3 as usize).wrapping_add(u).wrapping_add(2);
        let mut a = param_1;
        let mut b = param_2;
        loop {
            let sub: *mut u8 =
                core::ptr::read_unaligned(f.wrapping_add(8) as *const *mut u8);
            let inner: *mut u8 = core::ptr::read_unaligned(sub as *const *mut u8);
            let n4: u32 = core::ptr::read_unaligned(f.wrapping_add(4) as *const u32);
            fn_004057bc(a, b, inner, n4);
            let s: u32 = core::ptr::read_unaligned(f as *const u32);
            a = a.wrapping_add(s as usize);
            b = b.wrapping_add(s as usize);
            param_4 = param_4.wrapping_sub(1);
            if param_4 == 0 {
                break;
            }
        }
    } else if tag == 0x0e {
        let mut a = param_1;
        let mut b = param_2;
        loop {
            HOOK_0040567C(a, b, param_3);
            let u = core::ptr::read_unaligned(
                param_3.wrapping_byte_add(1) as *const u8,
            ) as usize;
            let s: u32 = core::ptr::read_unaligned(
                (param_3 as usize).wrapping_add(u).wrapping_add(2) as *const u32,
            );
            a = a.wrapping_add(s as usize);
            b = b.wrapping_add(s as usize);
            param_4 = param_4.wrapping_sub(1);
            if param_4 == 0 {
                break;
            }
        }
    } else if tag == 0x0f {
        let mut a = param_1;
        let mut b = param_2;
        loop {
            let v: usize = core::ptr::read_unaligned(b as *const usize);
            HOOK_0040628C(a, v);
            a = a.wrapping_add(4);
            b = b.wrapping_add(4);
            param_4 = param_4.wrapping_sub(1);
            if param_4 == 0 {
                break;
            }
        }
    } else if tag == 0x11 {
        let mut a = param_1;
        let mut b = param_2;
        loop {
            let v: usize = core::ptr::read_unaligned(b as *const usize);
            HOOK_00405B20(a, v, param_3);
            a = a.wrapping_add(4);
            b = b.wrapping_add(4);
            param_4 = param_4.wrapping_sub(1);
            if param_4 == 0 {
                break;
            }
        }
    } else {
        // MOV AL,2 over the 32-bit entry param_1 lane.
        TAIL_00402F60(((param_1 as u32) & 0xffffff00) | 2);
    }
}

#[cfg(test)]
mod tests {
    use super::{HOOK_00405664, TAIL_00402F60, fn_004057bc};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LANE_HITS: AtomicUsize = AtomicUsize::new(0);
    static LANE_LAST: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn lane(a: usize) {
        LANE_LAST.store(a, Ordering::SeqCst);
        LANE_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn tail(a: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(a as usize, Ordering::SeqCst);
    }

    #[test]
    fn stride_loop_and_fail_tail() {
        unsafe {
            HOOK_00405664 = lane;
            TAIL_00402F60 = tail;
        }
        // Tag 0x0c, count=2: lane(p1), lane(p1+0x10).
        let mut desc = [0x0cu8; 4];
        let mut p1 = [0u8; 64];
        let mut p2 = [0u8; 64];
        let (p1b, p2b) = (p1.as_mut_ptr() as usize, p2.as_mut_ptr() as usize);
        LANE_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_004057bc(p1b, p2b, desc.as_mut_ptr(), 2) };
        assert_eq!(LANE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(LANE_LAST.load(Ordering::SeqCst), p1b.wrapping_add(0x10));
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        // Unknown tag 0x07: fail tail over entry p1=0x12345678 ->
        // (0x12345678 & ~0xff) | 2 = 0x12345602.
        let mut bad = [0x07u8; 4];
        unsafe { fn_004057bc(0x12345678, p2b, bad.as_mut_ptr(), 3) };
        assert_eq!(LANE_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 0x12345602);
    }
}
