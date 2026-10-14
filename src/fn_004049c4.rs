//! Original procedure `0x004049c4` (151 bytes, `0x4049c4–0x404a5a`).
//! Evidence: `evidence/004049c4_fn_004049c4.md`.

unsafe extern "C" fn default_convert(_slot: *mut *mut u8, _src: *mut u8, _p3: i32) {}

unsafe extern "C" fn default_realloc(_slot: *mut *mut u8, _total: u32) {}

unsafe extern "C" fn default_oom(_base: *mut u8) {}

unsafe extern "C" fn default_alloc(_len: u32, _p3: u32) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_copy(_src: *mut u8, _dst: *mut u8, _n: u32) {}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Normalize target `0x404e94` (`FUN_00404e94`), called with
/// `(&tmp=0 out-slot, old *slot value, p3)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404e94` once it exists.
pub static mut HOOK_00404E94: unsafe extern "C" fn(*mut *mut u8, *mut u8, i32) =
    default_convert;

/// Realloc target `0x402e38` (`FUN_00402e38`), called with an in-out
/// slot initialized to `base` plus `total = len+13`.
///
/// ponytail: hook standing in for done `fn_00402e38`, rewire to real
/// call once cross-module linkage proven.
pub static mut HOOK_00402E38: unsafe extern "C" fn(*mut *mut u8, u32) = default_realloc;

/// OOM thunk `0x40380c` (`thunk_FUN_00402f60`), reached by terminal
/// `JMP` with `EAX=base` on `len+13` unsigned overflow.
///
/// ponytail: hook standing in for the thunk tail, rewire once the
/// target's return behavior is proven.
pub static mut HOOK_00402F60_OOM: unsafe extern "C" fn(*mut u8) = default_oom;

/// Alloc target `0x404774` (`FUN_00404774`), called with `(len, p3)`.
///
/// ponytail: hook standing in for unreconstructed callee, rewire to real
/// `fn_00404774` once it exists.
pub static mut HOOK_00404774: unsafe extern "C" fn(u32, u32) -> *mut u8 = default_alloc;

/// Copy target `0x402fbc` (`FUN_00402fbc`), called with
/// `(prev, newbuf, signed-min([prev-4], len))`.
///
/// ponytail: hook standing in for done `fn_00402fbc`, rewire to real
/// call once cross-module linkage proven.
pub static mut HOOK_00402FBC: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_copy;

/// Release target `0x4046c4` (`FUN_004046c4`), called with the slot
/// (tail path) or a stack copy of the old object (grow path).
///
/// ponytail: hook standing in for done `fn_004046c4`, rewire to real
/// call once cross-module linkage proven.
pub static mut HOOK_004046C4: unsafe extern "C" fn(*mut u8) = default_release;

/// Growable-buffer ensure: `len<=0` (signed) → release+store 0;
/// non-null `cur` with flag `i16 @-10 != 1` → normalize + XCHG;
/// count `u32 @-8 == 1` → grow in place (`len+13`, NUL at
/// `grown+len`); else alloc + signed-min copy, then release+store.
/// Negative offsets via `wrapping_byte_sub`; `[slot]` re-read after
/// every call (no caching); address math in `usize`.
///
/// ponytail: non-atomic host model of `XCHG`/`LOCK`, AtomicU32 once
/// threading proven.
pub unsafe fn fn_004049c4(slot: *mut *mut u8, len: u32, p3: i32) {
    let mut old: *mut u8 = core::ptr::null_mut();
    if (len as i32) > 0 {
        let mut cur: *mut u8 = core::ptr::read_unaligned(slot as *const *mut u8);
        if !cur.is_null() {
            if core::ptr::read_unaligned(cur.wrapping_byte_sub(10) as *const i16) != 1 {
                let mut tmp: *mut u8 = core::ptr::null_mut();
                let src: *mut u8 = core::ptr::read_unaligned(slot as *const *mut u8);
                HOOK_00404E94(&mut tmp, src, p3);
                cur = tmp;
                let prev: *mut u8 = core::ptr::read_unaligned(slot as *const *mut u8);
                core::ptr::write_unaligned(slot, tmp);
                old = prev;
            }
            if core::ptr::read_unaligned(cur.wrapping_byte_sub(8) as *const u32) == 1 {
                let base = cur.wrapping_byte_sub(12);
                let total = len.wrapping_add(13);
                if total < len {
                    HOOK_00402F60_OOM(base);
                    return;
                }
                let mut rs: *mut u8 = base;
                HOOK_00402E38(&mut rs, total);
                let grown = rs.wrapping_byte_add(12);
                core::ptr::write_unaligned(slot, grown);
                core::ptr::write_unaligned(grown.wrapping_byte_sub(4) as *mut u32, len);
                core::ptr::write_unaligned(grown.wrapping_add(len as usize), 0u8);
                if !old.is_null() {
                    let mut rel = old;
                    HOOK_004046C4(&mut rel as *mut *mut u8 as *mut u8);
                }
                return;
            }
        }
        let nb: *mut u8 = HOOK_00404774(len, p3 as u32);
        old = nb;
        let prev: *mut u8 = core::ptr::read_unaligned(slot as *const *mut u8);
        if !prev.is_null() {
            let pl: u32 = core::ptr::read_unaligned(prev.wrapping_byte_sub(4) as *const u32);
            let n = if (pl as i32) < (len as i32) { pl } else { len };
            HOOK_00402FBC(prev, nb, n);
        }
    }
    HOOK_004046C4(slot as *mut u8);
    core::ptr::write_unaligned(slot, old);
}

#[cfg(test)]
mod tests {
    use super::{
        HOOK_00402E38, HOOK_00402F60_OOM, HOOK_00402FBC, HOOK_004046C4, HOOK_00404774,
        HOOK_00404E94, fn_004049c4,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONV_HITS: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_HITS: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);
    static GOT_N: AtomicUsize = AtomicUsize::new(0);
    static GOT_REL: AtomicUsize = AtomicUsize::new(0);
    static mut TMP_OBJ: [u8; 24] = [0; 24];
    static mut NEW_BUF: [u8; 8] = [0; 8];

    unsafe extern "C" fn convert(out: *mut *mut u8, _src: *mut u8, _p3: i32) {
        CONV_HITS.fetch_add(1, Ordering::SeqCst);
        core::ptr::write_unaligned(
            out,
            (core::ptr::addr_of_mut!(TMP_OBJ) as *mut u8).wrapping_add(12),
        );
    }

    unsafe extern "C" fn realloc(_slot: *mut *mut u8, _total: u32) {
        REALLOC_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn alloc(_len: u32, _p3: u32) -> *mut u8 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        core::ptr::addr_of_mut!(NEW_BUF) as *mut u8
    }

    unsafe extern "C" fn copy(_src: *mut u8, _dst: *mut u8, n: u32) {
        COPY_HITS.fetch_add(1, Ordering::SeqCst);
        GOT_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn release(slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
        let obj: *mut u8 = core::ptr::read_unaligned(slot as *const *mut u8);
        GOT_REL.store(obj as usize, Ordering::SeqCst);
        core::ptr::write_unaligned(slot as *mut *mut u8, core::ptr::null_mut());
    }

    fn reset() {
        CONV_HITS.store(0, Ordering::SeqCst);
        REALLOC_HITS.store(0, Ordering::SeqCst);
        ALLOC_HITS.store(0, Ordering::SeqCst);
        COPY_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    /// Arena: obj = base+12; u16 @+0, i16 flag @+2, u32 count @+4,
    /// u32 datalen @+8; 12 payload bytes. Caller scope (pointers must
    /// not dangle).
    macro_rules! arena {
        ($a:ident, $base:ident, $obj:ident, $flag:expr, $count:expr, $data:expr) => {
            let mut $a = [0u8; 24];
            let $base = $a.as_mut_ptr();
            unsafe {
                core::ptr::write_unaligned($base.wrapping_add(2) as *mut i16, $flag);
                core::ptr::write_unaligned($base.wrapping_add(4) as *mut u32, $count);
                core::ptr::write_unaligned($base.wrapping_add(8) as *mut u32, $data);
            }
            let $obj: *mut u8 = $base.wrapping_add(12);
        };
    }

    #[test]
    fn ensure_lanes() {
        unsafe {
            HOOK_00404E94 = convert;
            HOOK_00402E38 = realloc;
            HOOK_00402F60_OOM = super::default_oom;
            HOOK_00404774 = alloc;
            HOOK_00402FBC = copy;
            HOOK_004046C4 = release;
        }
        let newbuf = core::ptr::addr_of_mut!(NEW_BUF) as *mut u8;
        // len=0 lane: tail release(null slot)+store 0.
        reset();
        let mut s0: *mut u8 = core::ptr::null_mut();
        let p0 = &mut s0 as *mut *mut u8;
        unsafe { fn_004049c4(p0, 0, 0) };
        assert!(s0.is_null());
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);

        // Null-slot alloc lane: no copy, tail stores newbuf.
        reset();
        let mut s1: *mut u8 = core::ptr::null_mut();
        let p1 = &mut s1 as *mut *mut u8;
        unsafe { fn_004049c4(p1, 4, 0) };
        assert_eq!(s1, newbuf);
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);

        // Copy lane (flag==1, count==2, datalen 9 > len 4):
        // signed-min copy n=4, tail release+store newbuf.
        reset();
        arena!(a2, _b2, o2, 1, 2, 9);
        let mut s2: *mut u8 = o2;
        let p2 = &mut s2 as *mut *mut u8;
        unsafe { fn_004049c4(p2, 4, 0) };
        assert_eq!(s2, newbuf);
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_N.load(Ordering::SeqCst), 4);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_REL.load(Ordering::SeqCst), o2 as usize);

        // Grow lane (flag==1, count==1): realloc passthrough,
        // [grown-4]=len, NUL at grown+len, old==0 so no release.
        reset();
        arena!(a3, b3, o3, 1, 1, 9);
        let mut s3: *mut u8 = o3;
        let p3 = &mut s3 as *mut *mut u8;
        unsafe { fn_004049c4(p3, 4, 0) };
        assert_eq!(s3, o3);
        assert_eq!(REALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(
            unsafe { core::ptr::read_unaligned(b3.wrapping_add(8) as *const u32) },
            4
        );
        assert_eq!(unsafe { *o3.wrapping_add(4) }, 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 0);

        // Normalize lane (flag==0): hook fills tmp (count==1 via TMP_OBJ
        // zero init? no — set it), XCHG stores tmp, grow path on tmp,
        // old released via stack copy.
        reset();
        unsafe {
            let tb = core::ptr::addr_of_mut!(TMP_OBJ) as *mut u8;
            core::ptr::write_unaligned(tb.wrapping_add(2) as *mut i16, 1);
            core::ptr::write_unaligned(tb.wrapping_add(4) as *mut u32, 1);
        }
        let tmp = unsafe { core::ptr::addr_of_mut!(TMP_OBJ) as *mut u8 }.wrapping_add(12);
        arena!(a4, _b4, o4, 0, 2, 9);
        let mut s4: *mut u8 = o4;
        let p4 = &mut s4 as *mut *mut u8;
        unsafe { fn_004049c4(p4, 4, 0) };
        assert_eq!(CONV_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(s4, tmp);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_REL.load(Ordering::SeqCst), o4 as usize);
    }
}
