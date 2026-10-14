//! Original procedure `0x00405548` (271 bytes, `0x00405548–0x00405656`).
//! Evidence: `evidence/00405548_fn_00405548.md`.

use core::ptr::{null_mut, read_unaligned};

unsafe extern "C" fn default_one(_p: *mut u8) {}

unsafe extern "C" fn default_two(_p: *mut u8, _n: u32) {}

unsafe extern "C" fn default_desc(_p: *mut u8, _d: *mut u8) {}

unsafe extern "C" fn default_fail(_arg: u32) -> *mut u8 {
    null_mut()
}

/// Target `0x004046c4` (`FUN_004046c4`), narrow `0x0a` lane.
///
/// ponytail: hook standing in for done `fn_004046c4`, rewire to real
/// call once cross-module test serialization exists.
pub static mut HOOK_004046c4: unsafe extern "C" fn(*mut u8) = default_one;

/// Target `0x004046e8` (`FUN_004046e8`), wide `0x0a` lane: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, u32)`).

/// Target `0x00404a8c` (`FUN_00404a8c`), narrow `0x0b` lane.
///
/// ponytail: hook standing in for done `fn_00404a8c`, rewire to real
/// call once cross-module test serialization exists.
pub static mut HOOK_00404a8c: unsafe extern "C" fn(*mut u8) = default_one;

/// Target `0x00404aa4` (`FUN_00404aa4`), wide `0x0b` lane.
///
/// ponytail: hook standing in for done `fn_00404aa4`, rewire to real
/// call once cross-module test serialization exists.
pub static mut HOOK_00404aa4: unsafe extern "C" fn(*mut u8, u32) = default_two;

/// Target `0x00404c88` (`thunk_FUN_004046c4`), narrow `0x12` lane.
///
/// ponytail: hook standing in for unreconstructed thunk; identity
/// with `fn_004046c4` unproven, keep separate until proven.
pub static mut HOOK_00404c88: unsafe extern "C" fn(*mut u8) = default_one;

/// Target `0x00404c90` (`thunk_FUN_004046e8`), wide `0x12` lane.
///
/// ponytail: hook standing in for unreconstructed thunk; identity
/// with `fn_004046e8` unproven, keep separate until proven.
pub static mut HOOK_00404c90: unsafe extern "C" fn(*mut u8, u32) = default_two;

/// Target `0x00405530` (`FUN_00405530`), `0x0c` loop body.
///
/// ponytail: hook standing in for same-batch `fn_00405530`, rewire to
/// the real call once both modules are linked.
pub static mut HOOK_00405530: unsafe extern "C" fn(*mut u8) = default_one;

/// Target `0x004054f8` (`FUN_004054f8`), `0x0e` loop body (outer desc).
///
/// ponytail: hook standing in for same-batch `fn_004054f8`, rewire to
/// the real call once both modules are linked.
pub static mut HOOK_004054f8: unsafe extern "C" fn(*mut u8, *mut u8) =
    default_desc;

/// Target `0x00406274` (`FUN_00406274`), `0x0f` loop body.
///
/// ponytail: hook standing in for unreconstructed callee, rewire once
/// it exists.
pub static mut HOOK_00406274: unsafe extern "C" fn(*mut u8) = default_one;

/// Target `0x00405ae4` (`FUN_00405ae4`), `0x11` loop body.
///
/// ponytail: hook standing in for unreconstructed callee, rewire once
/// it exists.
pub static mut HOOK_00405ae4: unsafe extern "C" fn(*mut u8, *mut u8) =
    default_desc;

/// Tail target `0x00402f60` (`FUN_00402f60`), default lane, reached with
/// `(base & ~0xff) | 2`; its result is the return.
///
/// ponytail: hook standing in for done `fn_00402f60`, rewire to real
/// call once cross-module test serialization exists. Low-32 lane is
/// exact; upper address bits are unobservable through the `u32` hook.
pub static mut HOOK_00402f60: unsafe extern "C" fn(u32) -> *mut u8 =
    default_fail;

/// Tag dispatch over `u8 [desc]` with `count`: `0` → return base;
/// `0x0a/0x12/0x0b` narrow (`count==1`, `HOOK` narrow) vs wide
/// (`(count as i32) > 1`, `HOOK` wide); `0x0c/0x0d/0x0e/0x0f/0x11`
/// `DEC; JG` loops with steps 16/stride/stride/4/4; default tails
/// `02f60`. Params arrive in EAX/EDX/ECX per Ghidra `__register`
/// observation. `0x0d` recurses directly; all other lanes hook.
pub unsafe fn fn_00405548(
    param_1: *mut u8,
    param_2: *mut u8,
    param_3: u32,
) -> *mut u8 {
    if param_3 == 0 {
        return param_1;
    }
    let tag: u8 = read_unaligned(param_2);
    let off = read_unaligned(param_2.wrapping_add(1)) as usize;
    match tag {
        0x0a => {
            if (param_3 as i32) > 1 {
                crate::fn_004046e8::fn_004046e8(param_1, param_3);
            } else {
                HOOK_004046c4(param_1);
            }
        }
        0x12 => {
            if (param_3 as i32) > 1 {
                HOOK_00404c90(param_1, param_3);
            } else {
                HOOK_00404c88(param_1);
            }
        }
        0x0b => {
            if (param_3 as i32) > 1 {
                HOOK_00404aa4(param_1, param_3);
            } else {
                HOOK_00404a8c(param_1);
            }
        }
        0x0c => {
            let mut pi = param_1;
            let mut n = param_3;
            loop {
                HOOK_00405530(pi);
                pi = pi.wrapping_add(16);
                n = n.wrapping_sub(1);
                if (n as i32) <= 0 {
                    break;
                }
            }
        }
        0x0d => {
            let mut pi = param_1;
            let mut n = param_3;
            loop {
                let stride: u32 = read_unaligned(
                    param_2.wrapping_add(off).wrapping_add(2) as *const u32,
                );
                let cnt: u32 = read_unaligned(
                    param_2.wrapping_add(off).wrapping_add(6) as *const u32,
                );
                let mid: *mut u8 = read_unaligned(
                    param_2.wrapping_add(off).wrapping_add(10) as *const *mut u8,
                );
                let sub: *mut u8 =
                    read_unaligned(mid as *const *mut u8);
                fn_00405548(pi, sub, cnt);
                pi = pi.wrapping_add(stride as usize);
                n = n.wrapping_sub(1);
                if (n as i32) <= 0 {
                    break;
                }
            }
        }
        0x0e => {
            let mut pi = param_1;
            let mut n = param_3;
            loop {
                let stride: u32 = read_unaligned(
                    param_2.wrapping_add(off).wrapping_add(2) as *const u32,
                );
                HOOK_004054f8(pi, param_2);
                pi = pi.wrapping_add(stride as usize);
                n = n.wrapping_sub(1);
                if (n as i32) <= 0 {
                    break;
                }
            }
        }
        0x0f => {
            let mut pi = param_1;
            let mut n = param_3;
            loop {
                HOOK_00406274(pi);
                pi = pi.wrapping_add(4);
                n = n.wrapping_sub(1);
                if (n as i32) <= 0 {
                    break;
                }
            }
        }
        0x11 => {
            let mut pi = param_1;
            let mut n = param_3;
            loop {
                HOOK_00405ae4(pi, param_2);
                pi = pi.wrapping_add(4);
                n = n.wrapping_sub(1);
                if (n as i32) <= 0 {
                    break;
                }
            }
        }
        _ => {
            return HOOK_00402f60(
                ((param_1 as usize as u32) & 0xffffff00) | 2,
            );
        }
    }
    param_1
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_00402f60, HOOK_004046c4, HOOK_00404a8c,
        HOOK_00404aa4, HOOK_00404c88, HOOK_00404c90, HOOK_004054f8,
        HOOK_00405530, HOOK_00405ae4, HOOK_00406274, fn_00405548,
    };
    use core::ptr::write_unaligned;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static ARG0: AtomicUsize = AtomicUsize::new(0);
    static ARG1: AtomicUsize = AtomicUsize::new(0);
    static ARG2: AtomicUsize = AtomicUsize::new(0);
    static FAIL_RET: AtomicUsize = AtomicUsize::new(0);

    static mut SEEN: [(usize, usize, usize); 4] = [(0, 0, 0); 4];

    unsafe fn note(a: usize, b: usize, c: usize) {
        let i = HITS.fetch_add(1, Ordering::SeqCst);
        if i < 4 {
            SEEN[i] = (a, b, c);
        }
    }

    unsafe extern "C" fn one(p: *mut u8) {
        note(p as usize, 0, 0);
        ARG0.store(p as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn two(p: *mut u8, n: u32) {
        note(p as usize, n as usize, 0);
        ARG0.store(p as usize, Ordering::SeqCst);
        ARG1.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn desc(p: *mut u8, d: *mut u8) {
        note(p as usize, d as usize, 0);
        ARG0.store(p as usize, Ordering::SeqCst);
        ARG1.store(d as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn fail(arg: u32) -> *mut u8 {
        note(arg as usize, 0, 0);
        ARG2.store(arg as usize, Ordering::SeqCst);
        FAIL_RET.load(Ordering::SeqCst) as *mut u8
    }

    fn tag_arena(tag: u8) -> [u8; 32] {
        let mut d = [0u8; 32];
        d[0] = tag;
        d[1] = 0;
        d
    }

    #[test]
    fn dispatch_lanes() {
        unsafe {
            HOOK_004046c4 = one;
            HOOK_00404a8c = one;
            HOOK_00404aa4 = two;
            HOOK_00404c88 = one;
            HOOK_00404c90 = two;
            HOOK_00405530 = one;
            HOOK_004054f8 = desc;
            HOOK_00406274 = one;
            HOOK_00405ae4 = desc;
            HOOK_00402f60 = fail;
        }
        let mut pi_arena = [0u8; 96];
        let pi = pi_arena.as_mut_ptr();

        // Count 0: returns base, nothing fires.
        let mut d = tag_arena(0x0a);
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405548(pi, d.as_mut_ptr(), 0) }, pi);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);

        // 0x0a narrow (real 46c4 stubbed) vs wide (real 46e8 over
        // the zeroed arena: all lanes null, no-op, returns base).
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405548(pi, d.as_mut_ptr(), 1) }, pi);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ARG0.load(Ordering::SeqCst), pi as usize);
        assert_eq!(unsafe { fn_00405548(pi, d.as_mut_ptr(), 3) }, pi);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);

        // 0x12 narrow/wide (thunk hooks, separate from 0x0a).
        let mut d = tag_arena(0x12);
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405548(pi, d.as_mut_ptr(), 1) }, pi);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { fn_00405548(pi, d.as_mut_ptr(), 2) }, pi);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
        assert_eq!(ARG1.load(Ordering::SeqCst), 2);

        // 0x0b narrow/wide.
        let mut d = tag_arena(0x0b);
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405548(pi, d.as_mut_ptr(), 1) }, pi);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { fn_00405548(pi, d.as_mut_ptr(), 4) }, pi);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
        assert_eq!(ARG1.load(Ordering::SeqCst), 4);

        // 0x0c loop: 3 calls, pi steps of 16.
        let mut d = tag_arena(0x0c);
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405548(pi, d.as_mut_ptr(), 3) }, pi);
        assert_eq!(HITS.load(Ordering::SeqCst), 3);
        unsafe {
            assert_eq!(SEEN[0].0, pi as usize);
            assert_eq!(SEEN[1].0, pi.wrapping_add(16) as usize);
            assert_eq!(SEEN[2].0, pi.wrapping_add(32) as usize);
        }

        // 0x0d: true self-recursion; [desc+10] points at a cell
        // holding the inner desc; inner tag 0x0a count 1 fires
        // HOOK_004046c4 with (pi, _, _); outer pi += 0x20.
        let mut inner = tag_arena(0x0a);
        let mut cell: *mut u8 = inner.as_mut_ptr();
        let mut d = tag_arena(0x0d);
        unsafe {
            let db = d.as_mut_ptr();
            write_unaligned(db.wrapping_add(2) as *mut u32, 0x20u32);
            write_unaligned(db.wrapping_add(6) as *mut u32, 1u32);
            write_unaligned(
                db.wrapping_add(10) as *mut *mut u8,
                &mut cell as *mut *mut u8 as *mut u8,
            );
            HITS.store(0, Ordering::SeqCst);
            assert_eq!(fn_00405548(pi, db, 2), pi);
            assert_eq!(HITS.load(Ordering::SeqCst), 2);
            assert_eq!(SEEN[0].0, pi as usize);
            assert_eq!(SEEN[1].0, pi.wrapping_add(0x20) as usize);
        }

        // 0x0e: sibling hook gets (pi, outer desc); pi += stride.
        let mut d = tag_arena(0x0e);
        unsafe {
            let db = d.as_mut_ptr();
            write_unaligned(db.wrapping_add(2) as *mut u32, 8u32);
            write_unaligned(db.wrapping_add(6) as *mut u32, 7u32);
            HITS.store(0, Ordering::SeqCst);
            assert_eq!(fn_00405548(pi, db, 2), pi);
            assert_eq!(HITS.load(Ordering::SeqCst), 2);
            assert_eq!(SEEN[0], (pi as usize, db as usize, 0));
            assert_eq!(SEEN[1], (pi.wrapping_add(8) as usize, db as usize, 0));
        }

        // 0x0f loop: step 4.
        let mut d = tag_arena(0x0f);
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405548(pi, d.as_mut_ptr(), 2) }, pi);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
        unsafe {
            assert_eq!(SEEN[0].0, pi as usize);
            assert_eq!(SEEN[1].0, pi.wrapping_add(4) as usize);
        }

        // 0x11 loop: (pi, desc), step 4.
        let mut d = tag_arena(0x11);
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405548(pi, d.as_mut_ptr(), 2) }, pi);
        assert_eq!(HITS.load(Ordering::SeqCst), 2);
        unsafe {
            assert_eq!(SEEN[0], (pi as usize, d.as_mut_ptr() as usize, 0));
            assert_eq!(
                SEEN[1],
                (pi.wrapping_add(4) as usize, d.as_mut_ptr() as usize, 0)
            );
        }

        // Default lane: tail arg (low32(base) & ~0xff)|2; its
        // result is the return.
        let mut d = tag_arena(0x77);
        let canned = pi.wrapping_add(64);
        FAIL_RET.store(canned as usize, Ordering::SeqCst);
        HITS.store(0, Ordering::SeqCst);
        assert_eq!(unsafe { fn_00405548(pi, d.as_mut_ptr(), 5) }, canned);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            ARG2.load(Ordering::SeqCst),
            (((pi as usize as u32) & 0xffffff00) | 2) as usize
        );
    }
}
