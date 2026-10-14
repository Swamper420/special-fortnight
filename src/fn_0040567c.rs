//! Original procedure `0x0040567c` (319 bytes, `0x0040567c–0x004057ba`).
//! Evidence: `evidence/0040567c_fn_0040567c.md`.

unsafe extern "C" fn default_ab(_a: usize, _b: usize) {}
unsafe extern "C" fn default_a(_a: usize) {}
unsafe extern "C" fn default_abc(_a: usize, _b: usize, _c: *mut u8) {}
unsafe extern "C" fn default_abcd(_a: usize, _b: usize, _c: *mut u8, _d: u32) {}
unsafe extern "C" fn default_tail(_a: u32) {}

/// Block copy `0x00402fbc` (`FUN_00402fbc`), lanes
/// `(param_2+off, param_1+off, len)` per `EAX/EDX/ECX` observation:
/// direct intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8, u32)`).

/// `0x00404718` lane (tag `0x0a`), args `(p1+i3, *(p2+i3))`.
///
/// ponytail: hook standing in for done `fn_00404718`, rewire to real
/// call once cross-module test serialization exists.
pub static mut HOOK_00404718: unsafe extern "C" fn(usize, usize) = default_ab;

/// `0x00404c98` lane (tag `0x12`), args `(p1+i3, *(p2+i3))`.
///
/// ponytail: hook standing in for done `fn_00404c98`, rewire to real
/// call once cross-module test serialization exists.
pub static mut HOOK_00404C98: unsafe extern "C" fn(usize, usize) = default_ab;

/// `0x00404ac8` lane (tag `0x0b`), args `(p1+i3, *(p2+i3))`.
///
/// ponytail: hook standing in for done `fn_00404ac8`, rewire to real
/// call once cross-module test serialization exists.
pub static mut HOOK_00404AC8: unsafe extern "C" fn(usize, usize) = default_ab;

/// `0x00405664` lane (tag `0x0c`), arg `(p1+i3)`.
///
/// ponytail: hook standing in for sibling `fn_00405664` (same work
/// package), rewire to real call once modules are declared.
pub static mut HOOK_00405664: unsafe extern "C" fn(usize) = default_a;

/// `0x004057bc` lane (tag `0x0d`), args `(p1+i3, p2+i3, **(pc+u+10),
/// *(pc+u+6))`; step is `*(pc+u+2)`.
///
/// ponytail: hook standing in for sibling `fn_004057bc` (same work
/// package), rewire to real call once modules are declared.
pub static mut HOOK_004057BC: unsafe extern "C" fn(usize, usize, *mut u8, u32) =
    default_abcd;

/// `0x0040628c` lane (tag `0x0f`), args `(p1+i3, *(p2+i3))`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_0040628c` once it exists.
pub static mut HOOK_0040628C: unsafe extern "C" fn(usize, usize) = default_ab;

/// `0x00405b20` lane (tag `0x11`), args `(p1+i3, *(p2+i3), pc)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to
/// real `fn_00405b20` once it exists.
pub static mut HOOK_00405B20: unsafe extern "C" fn(usize, usize, *mut u8) =
    default_abc;

/// Fail tail `0x00402f60` (`FUN_00402f60`), reached with `AL=2` over `i3`.
///
/// ponytail: hook standing in for done `fn_00402f60`, rewire to real
/// two-lane call once cross-module test serialization exists.
pub static mut TAIL_00402F60: unsafe extern "C" fn(u32) = default_tail;

unsafe fn gap_copy(p1: usize, p2: usize, cur: u32, off: u32) {
    let n = off.wrapping_sub(cur);
    if (n as i32) > 0 {
        crate::fn_00402fbc::fn_00402fbc(
            p2.wrapping_add(cur as usize) as *mut u8,
            p1.wrapping_add(cur as usize) as *mut u8,
            n,
        );
    }
}

/// Tag-dispatched range filler over the `(limit, count)` header at
/// `param_3 + byte(param_3+1) + 10`. Params arrive in EAX/EDX/ECX per
/// Ghidra `__register` observation; bases stay `usize` (never `as u32`
/// on pointers), dword slots stay `u32`.
pub unsafe fn fn_0040567c(param_1: usize, param_2: usize, param_3: *mut u8) {
    let u = core::ptr::read_unaligned(param_3.wrapping_byte_add(1) as *const u8)
        as usize;
    let tbl = (param_3 as usize).wrapping_add(u).wrapping_add(10);
    let mut count: u32 = core::ptr::read_unaligned(tbl.wrapping_sub(4) as *const u32);
    let limit: u32 = core::ptr::read_unaligned(tbl.wrapping_sub(8) as *const u32);
    let mut cur: u32 = 0;
    // Entries are (link, off): link pointer-sized, off dword at +8,
    // 16-byte stride on the host (8-byte image stride).
    let mut t = tbl;
    if count == 0 {
        gap_copy(param_1, param_2, cur, limit);
        return;
    }
    loop {
        let off: u32 = core::ptr::read_unaligned(t.wrapping_add(8) as *const u32);
        gap_copy(param_1, param_2, cur, off);
        let i3 = off;
        let link: *mut u8 = core::ptr::read_unaligned(t as *const *mut u8);
        let pc: *mut u8 = core::ptr::read_unaligned(link as *const *mut u8);
        let tag: u8 = core::ptr::read_unaligned(pc as *const u8);
        let delta: u32 = if tag == 0x0a {
            let v: usize =
                core::ptr::read_unaligned(param_2.wrapping_add(i3 as usize) as *const usize);
            HOOK_00404718(param_1.wrapping_add(i3 as usize), v);
            4
        } else if tag == 0x12 {
            let v: usize =
                core::ptr::read_unaligned(param_2.wrapping_add(i3 as usize) as *const usize);
            HOOK_00404C98(param_1.wrapping_add(i3 as usize), v);
            4
        } else if tag == 0x0b {
            let v: usize =
                core::ptr::read_unaligned(param_2.wrapping_add(i3 as usize) as *const usize);
            HOOK_00404AC8(param_1.wrapping_add(i3 as usize), v);
            4
        } else if tag == 0x0c {
            HOOK_00405664(param_1.wrapping_add(i3 as usize));
            0x10
        } else if tag == 0x0d {
            let u2 = core::ptr::read_unaligned(pc.wrapping_byte_add(1) as *const u8)
                as usize;
            let f = (pc as usize).wrapping_add(u2).wrapping_add(2);
            let step: u32 = core::ptr::read_unaligned(f as *const u32);
            let n4: u32 =
                core::ptr::read_unaligned(f.wrapping_add(4) as *const u32);
            let sub: *mut u8 =
                core::ptr::read_unaligned(f.wrapping_add(8) as *const *mut u8);
            let inner: *mut u8 = core::ptr::read_unaligned(sub as *const *mut u8);
            HOOK_004057BC(
                param_1.wrapping_add(i3 as usize),
                param_2.wrapping_add(i3 as usize),
                inner,
                n4,
            );
            step
        } else if tag == 0x0e {
            let u2 = core::ptr::read_unaligned(pc.wrapping_byte_add(1) as *const u8)
                as usize;
            let step: u32 = core::ptr::read_unaligned(
                (pc as usize).wrapping_add(u2).wrapping_add(2) as *const u32,
            );
            fn_0040567c(
                param_1.wrapping_add(i3 as usize),
                param_2.wrapping_add(i3 as usize),
                pc,
            );
            step
        } else if tag == 0x0f {
            let v: usize =
                core::ptr::read_unaligned(param_2.wrapping_add(i3 as usize) as *const usize);
            HOOK_0040628C(param_1.wrapping_add(i3 as usize), v);
            4
        } else if tag == 0x11 {
            let v: usize =
                core::ptr::read_unaligned(param_2.wrapping_add(i3 as usize) as *const usize);
            HOOK_00405B20(param_1.wrapping_add(i3 as usize), v, pc);
            4
        } else {
            TAIL_00402F60((i3 & 0xffffff00) | 2);
            return;
        };
        cur = delta.wrapping_add(i3);
        t = t.wrapping_add(16);
        count = count.wrapping_sub(1);
        if count == 0 {
            break;
        }
    }
    gap_copy(param_1, param_2, cur, limit);
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_00405664, TAIL_00402F60, fn_0040567c,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LANE_HITS: AtomicUsize = AtomicUsize::new(0);
    static LANE_ARG: AtomicUsize = AtomicUsize::new(0);
    static TAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static TAIL_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn lane(a: usize) {
        LANE_HITS.fetch_add(1, Ordering::SeqCst);
        LANE_ARG.store(a, Ordering::SeqCst);
    }

    unsafe extern "C" fn tail(a: u32) {
        TAIL_HITS.fetch_add(1, Ordering::SeqCst);
        TAIL_ARG.store(a as usize, Ordering::SeqCst);
    }

    /// Build `desc` with header `(limit, count)` at `desc+u+10-8`
    /// and one 16-byte entry `(link, off)`; link points at a cell
    /// holding the tag pointer (double deref, both levels).
    unsafe fn plant(
        desc: *mut u8,
        u: usize,
        limit: u32,
        count: u32,
        cell: *mut u8,
        tag: *mut u8,
        off: u32,
    ) {
        core::ptr::write_unaligned(desc.wrapping_byte_add(1), u as u8);
        let tbl = (desc as usize).wrapping_add(u).wrapping_add(10);
        core::ptr::write_unaligned(tbl.wrapping_sub(8) as *mut u32, limit);
        core::ptr::write_unaligned(tbl.wrapping_sub(4) as *mut u32, count);
        core::ptr::write_unaligned(cell as *mut *mut u8, tag);
        core::ptr::write_unaligned(tbl as *mut *mut u8, cell);
        core::ptr::write_unaligned(tbl.wrapping_add(8) as *mut u32, off);
    }

    #[test]
    fn lane_step_and_fail_tail() {
        unsafe {
            HOOK_00405664 = lane;
            TAIL_00402F60 = tail;
        }
        let mut desc = [0u8; 40];
        let mut tag0c = [0x0cu8; 4];
        let mut cell: *mut u8 = core::ptr::null_mut();
        let (d, t, c) = (desc.as_mut_ptr(), tag0c.as_mut_ptr(), &mut cell as *mut *mut u8 as *mut u8);
        let mut p1 = [0u8; 32];
        let mut p2 = [0u8; 32];
        let (p1b, p2b) = (p1.as_mut_ptr() as usize, p2.as_mut_ptr() as usize);

        // count=1, limit=0x10, off=0, tag 0x0c: no gap copy, lane(p1),
        // cur=0x10, tail gap 0 -> no copy, no fail tail.
        LANE_HITS.store(0, Ordering::SeqCst);
        TAIL_HITS.store(0, Ordering::SeqCst);
        unsafe { plant(d, 0, 0x10, 1, c, t, 0) };
        unsafe { fn_0040567c(p1b, p2b, d) };
        assert_eq!(LANE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LANE_ARG.load(Ordering::SeqCst), p1b);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 0);

        // Unknown tag, off=16: head gap (16) moves 16 real bytes
        // p2→p1, then fail tail over i3=16 -> (16 & ~0xff)|2 = 2.
        let mut tagxx = [0x00u8; 4];
        for (i, b) in p2.iter_mut().enumerate() {
            *b = (0xA0 + i) as u8;
        }
        p1.fill(0);
        unsafe { plant(d, 0, 0x20, 1, c, tagxx.as_mut_ptr(), 16) };
        unsafe { fn_0040567c(p1b, p2b, d) };
        assert_eq!(&p1[..16], &p2[..16]);
        assert_eq!(TAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TAIL_ARG.load(Ordering::SeqCst), 2);
    }
}
