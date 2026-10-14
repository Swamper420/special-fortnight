//! Original procedure `0x00404f00` (151 bytes, `0x00404f00–0x00404f96`).
//! Evidence: `evidence/00404f00_fn_00404f00.md`.

use crate::fn_004046c4::fn_004046c4;

unsafe extern "C" fn default_normalize(_slot: *mut u8, _src: *mut u8) {}

unsafe extern "C" fn default_realloc(_slot: *mut *mut u8, _total: u32) {}

unsafe extern "C" fn default_alloc(_n: u32) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_copy(_src: *mut u8, _dst: *mut u8, _n: u32) {}

unsafe extern "C" fn default_fail(_base: *mut u8) {}

/// Normalize target `0x00404e6c` (`FUN_00404e6c`), called with
/// `(&tmp=0 out-slot, old *slot value)` on the foreign-tag lane.
///
/// ponytail: hook standing in for same-batch `fn_00404e6c`,
/// rewire to the real call once cross-module linkage proven.
pub static mut HOOK_00404e6c: unsafe extern "C" fn(*mut u8, *mut u8) = default_normalize;

/// Realloc target `0x00402e38` (`FUN_00402e38`), called with an
/// in-out slot initialized to `base` plus `total = count*2+14`.
///
/// ponytail: hook standing in for done `fn_00402e38` (which owns
/// unreconstructed import state), rewire to the real call once
/// cross-module test serialization exists.
pub static mut HOOK_00402e38: unsafe extern "C" fn(*mut *mut u8, u32) = default_realloc;

/// Alloc target `0x004054b4` (`FUN_004054b4`), called with `count`,
/// result stored to the slot by the tail.
///
/// ponytail: hook standing in for unreconstructed callee, rewire
/// to real `fn_004054b4` once it exists. Returns the DATA
/// pointer (base+12), never the header base.
pub static mut HOOK_004054b4: unsafe extern "C" fn(u32) -> *mut u8 = default_alloc;

/// Copy target `0x00402fbc` (`FUN_00402fbc`), called with
/// `(prev, newbuf, signed-min([prev-4], count)<<1)`.
///
/// ponytail: hook standing in for done `fn_00402fbc`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00402fbc: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_copy;

/// Overflow arm `0x0040380c` (`thunk_FUN_00402f60`), terminal `JMP`
/// with `EAX=base` when `count*2` or `+14` signed-overflows.
///
/// ponytail: hook standing in for the thunk tail; call+return
/// models the `JMP` per decompiler, diverge-only-if-noreturn.
pub static mut FAIL_00402F60: unsafe extern "C" fn(*mut u8) = default_fail;

/// x86 `ADD` signed-overflow (`JO`) predicate.
fn of_add(a: u32, b: u32) -> bool {
    let r = a.wrapping_add(b);
    ((a ^ r) & (b ^ r) & 0x8000_0000) != 0
}

/// Growable wide-string ensure: `count<=0` (signed) → release+store
/// 0; non-null `cur` with tag `u16 @-10 != 2` → normalize + XCHG;
/// count `u32 @-8 == 1` → grow in place (`count*2+14`, NUL word at
/// `grown+count*2`); else alloc + signed-min copy, then release+store.
/// `param_1` (slot) arrives in EAX, `param_2` (count) in EDX per
/// Ghidra `__register` observation. Negative offsets via
/// `wrapping_byte_offset` (sign-extended); `[slot]` re-read after
/// every call (no caching); pointer loads `: *mut u8`
/// (pointer-sized links); count/len words stay `u32`, tag `u16`;
/// `count*2`/`+14` use `wrapping_*` with `JO`-exact `of_add`
/// guards; signed-min copy uses `(pl as i32) < (count as i32)`
/// (`JL`); old-release goes through a stack copy. Direct call to
/// done `fn_004046c4` (no hook).
///
/// ponytail: non-atomic host model of `XCHG`/`LOCK`, AtomicU32 once
/// threading proven.
pub unsafe fn fn_00404f00(slot: *mut *mut u8, count: u32) {
    let mut old: *mut u8 = core::ptr::null_mut();
    if (count as i32) > 0 {
        let mut cur: *mut u8 = core::ptr::read_unaligned(slot as *const *mut u8);
        if !cur.is_null() {
            if core::ptr::read_unaligned(cur.wrapping_byte_offset(-10) as *const u16) != 2 {
                let mut tmp: *mut u8 = core::ptr::null_mut();
                let src: *mut u8 = core::ptr::read_unaligned(slot as *const *mut u8);
                HOOK_00404e6c(&mut tmp as *mut *mut u8 as *mut u8, src);
                cur = tmp;
                let prev: *mut u8 = core::ptr::read_unaligned(slot as *const *mut u8);
                core::ptr::write_unaligned(slot, tmp);
                old = prev;
            }
            if core::ptr::read_unaligned(cur.wrapping_byte_offset(-8) as *const u32) == 1 {
                let base = cur.wrapping_byte_offset(-12);
                let doubled = count.wrapping_mul(2);
                if of_add(count, count) {
                    FAIL_00402F60(base);
                    return;
                }
                let total = doubled.wrapping_add(0xe);
                if of_add(doubled, 0xe) {
                    FAIL_00402F60(base);
                    return;
                }
                let mut rs: *mut u8 = base;
                HOOK_00402e38(&mut rs, total);
                let grown = rs.wrapping_byte_offset(12);
                core::ptr::write_unaligned(slot, grown);
                core::ptr::write_unaligned(grown.wrapping_byte_offset(-4) as *mut u32, count);
                core::ptr::write_unaligned(
                    grown.wrapping_byte_add((count as usize).wrapping_mul(2)) as *mut u16,
                    0,
                );
                if !old.is_null() {
                    let mut rel = old;
                    fn_004046c4(&mut rel as *mut *mut u8 as *mut u8);
                }
                return;
            }
        }
        let nb: *mut u8 = HOOK_004054b4(count);
        old = nb;
        let prev: *mut u8 = core::ptr::read_unaligned(slot as *const *mut u8);
        if !prev.is_null() {
            let pl: u32 = core::ptr::read_unaligned(prev.wrapping_byte_offset(-4) as *const u32);
            let n = if (pl as i32) < (count as i32) { pl } else { count };
            HOOK_00402fbc(prev, nb, n.wrapping_shl(1));
        }
    }
    fn_004046c4(slot as *mut u8);
    core::ptr::write_unaligned(slot, old);
}

#[cfg(test)]
mod tests {
    use super::{
        FAIL_00402F60, HOOK_00402e38, HOOK_00402fbc, HOOK_00404e6c, HOOK_004054b4, fn_00404f00,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NORM_HITS: AtomicUsize = AtomicUsize::new(0);
    static NORM_TMP: AtomicUsize = AtomicUsize::new(0);
    static NORM_SRC: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_TOTAL: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static COPY_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_SRC: AtomicUsize = AtomicUsize::new(0);
    static COPY_DST: AtomicUsize = AtomicUsize::new(0);
    static COPY_N: AtomicUsize = AtomicUsize::new(0);
    static FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FAIL_ARG: AtomicUsize = AtomicUsize::new(0);
    static NORM_RET: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn normalize(out: *mut u8, src: *mut u8) {
        NORM_HITS.fetch_add(1, Ordering::SeqCst);
        NORM_TMP.store(out as usize, Ordering::SeqCst);
        NORM_SRC.store(src as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(
            out as *mut *mut u8,
            NORM_RET.load(Ordering::SeqCst) as *mut u8,
        );
    }

    unsafe extern "C" fn realloc(_slot: *mut *mut u8, total: u32) {
        REALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        REALLOC_TOTAL.store(total as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn alloc(n: u32) -> *mut u8 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        ALLOC_RET.load(Ordering::SeqCst) as *mut u8
    }

    unsafe extern "C" fn copy(src: *mut u8, dst: *mut u8, n: u32) {
        COPY_HITS.fetch_add(1, Ordering::SeqCst);
        COPY_SRC.store(src as usize, Ordering::SeqCst);
        COPY_DST.store(dst as usize, Ordering::SeqCst);
        COPY_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn fail(base: *mut u8) {
        FAIL_HITS.fetch_add(1, Ordering::SeqCst);
        FAIL_ARG.store(base as usize, Ordering::SeqCst);
    }

    /// Arena: obj = base+12; tag u16 @+2 (`obj-10`), refcount u32
    /// @+4 (`obj-8`), len u32 @+8 (`obj-4`); 20 payload bytes for
    /// the emulated NUL-word write. Caller scope (pointers must
    /// not dangle).
    macro_rules! arena {
        ($a:ident, $base:ident, $obj:ident, $tag:expr, $count:expr, $data:expr) => {
            let mut $a = [0u8; 32];
            let $base = $a.as_mut_ptr();
            unsafe {
                core::ptr::write_unaligned($base.wrapping_add(2) as *mut u16, $tag);
                core::ptr::write_unaligned($base.wrapping_add(4) as *mut u32, $count);
                core::ptr::write_unaligned($base.wrapping_add(8) as *mut u32, $data);
            }
            let $obj: *mut u8 = $base.wrapping_add(12);
        };
    }

    fn reset() {
        NORM_HITS.store(0, Ordering::SeqCst);
        REALLOC_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        COPY_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn ensure_lanes() {
        // Shared fn_00404dd4 hooks: hold the common owner lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        unsafe {
            HOOK_00404e6c = normalize;
            HOOK_00402e38 = realloc;
            HOOK_004054b4 = alloc;
            HOOK_00402fbc = copy;
            FAIL_00402F60 = fail;
        }
        // count=0 lane: tail release (old rc 2→1, no dtor) + store 0.
        reset();
        arena!(a0, _b0, o0, 2, 2, 9);
        let mut s0: *mut u8 = o0;
        let p0 = &mut s0 as *mut *mut u8;
        unsafe { fn_00404f00(p0, 0) };
        assert!(s0.is_null());
        assert_eq!(unsafe { core::ptr::read_unaligned(_b0.wrapping_add(4) as *const u32) }, 1);
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // Null-slot alloc lane: alloc(5), no copy, tail stores newbuf.
        reset();
        arena!(a1, _b1, _o1, 2, 1, 0);
        let nb1 = _o1;
        ALLOC_RET.store(nb1 as usize, Ordering::SeqCst);
        let mut s1: *mut u8 = core::ptr::null_mut();
        let p1 = &mut s1 as *mut *mut u8;
        unsafe { fn_00404f00(p1, 5) };
        assert_eq!(s1, nb1);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 5);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);

        // Copy lane (tag==2, old count==2, prev len 9 > count
        // 4): signed-min copy n=4<<1=8, tail release+store newbuf.
        reset();
        arena!(a2, b2, o2, 2, 2, 9);
        arena!(an2, _bn2, _on2, 2, 1, 0);
        let nb2 = _on2;
        ALLOC_RET.store(nb2 as usize, Ordering::SeqCst);
        let mut s2: *mut u8 = o2;
        let p2 = &mut s2 as *mut *mut u8;
        unsafe { fn_00404f00(p2, 4) };
        assert_eq!(s2, nb2);
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_SRC.load(Ordering::SeqCst), o2 as usize);
        assert_eq!(COPY_DST.load(Ordering::SeqCst), nb2 as usize);
        assert_eq!(COPY_N.load(Ordering::SeqCst), 8);
        assert_eq!(unsafe { core::ptr::read_unaligned(b2.wrapping_add(4) as *const u32) }, 1);

        // Grow lane (tag==2, count==1): realloc passthrough with
        // total 5*2+14=24, [grown-4]=5, NUL word at grown+10,
        // old==0 so no release and the tail store is skipped.
        reset();
        arena!(a3, b3, o3, 2, 1, 9);
        let mut s3: *mut u8 = o3;
        let p3 = &mut s3 as *mut *mut u8;
        unsafe { fn_00404f00(p3, 5) };
        assert_eq!(s3, o3);
        assert_eq!(REALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(REALLOC_TOTAL.load(Ordering::SeqCst), 24);
        assert_eq!(unsafe { core::ptr::read_unaligned(b3.wrapping_add(8) as *const u32) }, 5);
        assert_eq!(unsafe { core::ptr::read_unaligned(o3.wrapping_add(10) as *const u16) }, 0);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // Normalize lane (foreign tag): hook fills tmp, XCHG stores
        // tmp, old (rc 2→1) released via stack copy, grow on tmp.
        reset();
        arena!(a4, b4, o4, 7, 0, 9);
        arena!(at4, _bt4, ot4, 2, 1, 0);
        NORM_RET.store(ot4 as usize, Ordering::SeqCst);
        let mut s4: *mut u8 = o4;
        let old4 = o4;
        let p4 = &mut s4 as *mut *mut u8;
        // Old rc must survive the release: seed 2.
        unsafe { core::ptr::write_unaligned(b4.wrapping_add(4) as *mut u32, 2) };
        unsafe { fn_00404f00(p4, 5) };
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(NORM_SRC.load(Ordering::SeqCst), old4 as usize);
        assert_eq!(s4, ot4);
        assert_eq!(unsafe { core::ptr::read_unaligned(b4.wrapping_add(4) as *const u32) }, 1);
        assert_eq!(REALLOC_TOTAL.load(Ordering::SeqCst), 24);

        // Overflow lanes: count=0x40000000 trips count*2 (OF),
        // count=0x3FFFFFFF trips +14 (OF); both fail with base.
        for count in [0x4000_0000u32, 0x3FFF_FFFFu32] {
            reset();
            arena!(ao, bo, oo, 2, 1, 0);
            let mut so: *mut u8 = oo;
            let po = &mut so as *mut *mut u8;
            unsafe { fn_00404f00(po, count) };
            assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 1);
            assert_eq!(FAIL_ARG.load(Ordering::SeqCst), bo as usize);
            assert_eq!(REALLOC_HITS.load(Ordering::SeqCst), 0);
            assert_eq!(so, oo);
        }
    }
}
