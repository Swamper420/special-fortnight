//! Original procedure `0x00404f98` (191 bytes, `0x404f98–0x405056`).
//! Evidence: `evidence/00404f98_fn_00404f98.md`.

use crate::fn_004046c4::fn_004046c4;
use crate::fn_00404830::fn_00404830;
use crate::fn_0040493c::fn_0040493c;
use crate::fn_00404c98::fn_00404c98;

unsafe extern "C" fn default_size(_slot: *mut u8, _n: u32) {}

unsafe extern "C" fn default_copy(_src: *mut u8, _dst: *mut u8, _n: u32) {}

unsafe extern "C" fn default_fail(_arg: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Size target `0x404f00` (`FUN_00404f00`), called with
/// `(slot, oldlen+srclen)` (concat) or `(slot, oldlen*2)` (self).
///
/// ponytail: hook standing in for same-batch `fn_00404f00`,
/// rewire to the real call once cross-module linkage proven.
pub static mut HOOK_00404f00: unsafe extern "C" fn(*mut u8, u32) = default_size;

/// Copy target `0x402fbc` (`FUN_00402fbc`), called with
/// `(src, newdata+oldlen*2, srclen*2)`.
///
/// ponytail: hook standing in for done `fn_00402fbc`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00402fbc: unsafe extern "C" fn(*mut u8, *mut u8, u32) = default_copy;

/// Overflow arm `0x40380c` (`thunk_FUN_00402f60`), terminal `JMP`
/// when the length sum has either of the top two bits set;
/// returns the pointer the decompiler threads through.
///
/// ponytail: hook standing in for the thunk tail; call+return
/// models the `JMP` per decompiler, diverge-only-if-noreturn.
pub static mut FAIL_00402F60: unsafe extern "C" fn(*mut u8) -> *mut u8 = default_fail;

/// Wide-string append: `src==0 → slot`; `*slot==0 → tail
/// 4c98(slot,src)`; `src==*slot` → self-double (`4f00(slot,
/// oldlen*2)`, copy within the grown buffer); else concat
/// (`4f00(slot,oldlen+srclen)`, copy `srclen` after `oldlen`).
/// Foreign tags normalize first (`4830(slot)` result for old,
/// `AddRef`+`4830(&local)` for src); top-two-bits on the sum
/// takes the fail arm. `param_1` (slot) arrives in EAX,
/// `param_2` (src) in EDX per Ghidra `__register` observation.
/// Negative offsets via `wrapping_byte_offset` (sign-extended);
/// `[slot]`/`[src-4]` re-read after every call (no caching);
/// pointer loads `: *mut u8` (pointer-sized links); lengths
/// stay `u32`, tags `u16`; sums use `wrapping_*`. Direct calls
/// to done `fn_004046c4`/`fn_00404830`/`fn_0040493c`/`fn_00404c98`
/// (no hooks).
///
/// ponytail: non-atomic host model of `XCHG`/`LOCK`, AtomicU32
/// once threading proven.
pub unsafe fn fn_00404f98(param_1: *mut u8, param_2: *mut u8) -> *mut u8 {
    if param_2.is_null() {
        return param_1;
    }
    let cur: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    if cur.is_null() {
        fn_00404c98(param_1, param_2);
        return param_1;
    }
    if param_2 == cur {
        let mut work = cur;
        if core::ptr::read_unaligned(cur.wrapping_byte_offset(-10) as *const u16) != 2 {
            work = fn_00404830(param_1 as *mut u32) as usize as *mut u8;
        }
        let oldlen: u32 = core::ptr::read_unaligned(work.wrapping_byte_offset(-4) as *const u32);
        let total = oldlen.wrapping_shl(1);
        if (total & 0xc000_0000) != 0 {
            return FAIL_00402F60(param_1);
        }
        HOOK_00404f00(param_1, total);
        let newdata: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
        HOOK_00402fbc(
            newdata,
            newdata.wrapping_byte_add((oldlen as usize).wrapping_mul(2)),
            oldlen.wrapping_shl(1),
        );
        // No local slot on this path: `POP EAX` pops the pushed 0.
        return core::ptr::null_mut();
    }
    let mut work = cur;
    if core::ptr::read_unaligned(cur.wrapping_byte_offset(-10) as *const u16) != 2 {
        work = fn_00404830(param_1 as *mut u32) as usize as *mut u8;
    }
    let mut local: *mut u8 = core::ptr::null_mut();
    let mut src = param_2;
    if core::ptr::read_unaligned(src.wrapping_byte_offset(-10) as *const u16) != 2 {
        local = src;
        fn_0040493c(src);
        fn_00404830(&mut local as *mut *mut u8 as *mut u32);
        src = local;
    }
    let oldlen: u32 = core::ptr::read_unaligned(work.wrapping_byte_offset(-4) as *const u32);
    let srclen: u32 = core::ptr::read_unaligned(src.wrapping_byte_offset(-4) as *const u32);
    let total = srclen.wrapping_add(oldlen);
    if (total & 0xc000_0000) != 0 {
        return FAIL_00402F60(&mut local as *mut *mut u8 as *mut u8);
    }
    HOOK_00404f00(param_1, total);
    let n: u32 = core::ptr::read_unaligned(src.wrapping_byte_offset(-4) as *const u32);
    let newdata: *mut u8 = core::ptr::read_unaligned(param_1 as *const *mut u8);
    HOOK_00402fbc(
        src,
        newdata.wrapping_byte_add((oldlen as usize).wrapping_mul(2)),
        n.wrapping_shl(1),
    );
    if !local.is_null() {
        fn_004046c4(&mut local as *mut *mut u8 as *mut u8);
    }
    local
}

#[cfg(test)]
mod tests {
    use super::{FAIL_00402F60, HOOK_00402fbc, HOOK_00404f00, fn_00404f98};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SIZE_HITS: AtomicUsize = AtomicUsize::new(0);
    static SIZE_ARG: AtomicUsize = AtomicUsize::new(0);
    static COPY_HITS: AtomicUsize = AtomicUsize::new(0);
    static COPY_SRC: AtomicUsize = AtomicUsize::new(0);
    static COPY_DST: AtomicUsize = AtomicUsize::new(0);
    static COPY_N: AtomicUsize = AtomicUsize::new(0);
    static FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static FAIL_RET: AtomicUsize = AtomicUsize::new(0);
    static SIZE_BUF: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn size(slot: *mut u8, n: u32) {
        SIZE_HITS.fetch_add(1, Ordering::SeqCst);
        SIZE_ARG.store(n as usize, Ordering::SeqCst);
        // Emulate the grow: store the canned new DATA pointer.
        core::ptr::write_unaligned(
            slot as *mut *mut u8,
            SIZE_BUF.load(Ordering::SeqCst) as *mut u8,
        );
    }

    unsafe extern "C" fn copy(src: *mut u8, dst: *mut u8, n: u32) {
        COPY_HITS.fetch_add(1, Ordering::SeqCst);
        COPY_SRC.store(src as usize, Ordering::SeqCst);
        COPY_DST.store(dst as usize, Ordering::SeqCst);
        COPY_N.store(n as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn fail(_arg: *mut u8) -> *mut u8 {
        FAIL_HITS.fetch_add(1, Ordering::SeqCst);
        FAIL_RET.load(Ordering::SeqCst) as *mut u8
    }

    /// Arena: obj = base+12 (the DATA pointer hooks return); tag
    /// u16 @+2 (`obj-10`), refcount u32 @+4 (`obj-8`), len u32
    /// @+8 (`obj-4`). Caller scope (pointers must not dangle).
    macro_rules! arena {
        ($a:ident, $obj:ident, $tag:expr, $count:expr, $data:expr) => {
            let mut $a = [0u8; 32];
            let $obj: *mut u8 = {
                let base = $a.as_mut_ptr();
                unsafe {
                    core::ptr::write_unaligned(base.wrapping_add(2) as *mut u16, $tag);
                    core::ptr::write_unaligned(base.wrapping_add(4) as *mut u32, $count);
                    core::ptr::write_unaligned(base.wrapping_add(8) as *mut u32, $data);
                }
                base.wrapping_add(12)
            };
        };
    }

    fn reset() {
        SIZE_HITS.store(0, Ordering::SeqCst);
        COPY_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn append_lanes() {
        unsafe {
            HOOK_00404f00 = size;
            HOOK_00402fbc = copy;
            FAIL_00402F60 = fail;
        }
        // Null-src lane: returns the slot pointer, nothing fires.
        reset();
        let mut s0: *mut u8 = 0x1234 as *mut u8;
        let p0 = &mut s0 as *mut *mut u8 as *mut u8;
        let ret = unsafe { fn_00404f98(p0, core::ptr::null_mut()) };
        assert_eq!(ret, p0);
        assert_eq!(s0 as usize, 0x1234);
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 0);

        // Null-slot lane: tail 4c98 acquires src (rc 5→6); old
        // null so no dtor hook; returns the slot pointer.
        reset();
        arena!(a1, o1, 2, 5, 8);
        let mut s1: *mut u8 = core::ptr::null_mut();
        let p1 = &mut s1 as *mut *mut u8 as *mut u8;
        let ret = unsafe { fn_00404f98(p1, o1) };
        assert_eq!(ret, p1);
        assert_eq!(s1, o1);
        assert_eq!(unsafe { core::ptr::read_unaligned(o1.wrapping_byte_offset(-8) as *const u32) }, 6);
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 0);

        // Concat lane (both tag==2, no normalize hooks): total
        // 3+4=7; copy (src, new+3*2, 4*2); local stays null so no
        // release and src rc is untouched; returns null.
        reset();
        arena!(aw, ow, 2, 1, 3);
        arena!(asrc, osrc, 2, 2, 4);
        arena!(anew, onew, 2, 1, 0);
        unsafe { SIZE_BUF.store(onew as usize, Ordering::SeqCst) };
        let mut s2: *mut u8 = ow;
        let p2 = &mut s2 as *mut *mut u8 as *mut u8;
        let ret = unsafe { fn_00404f98(p2, osrc) };
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SIZE_ARG.load(Ordering::SeqCst), 7);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_SRC.load(Ordering::SeqCst), osrc as usize);
        assert_eq!(COPY_DST.load(Ordering::SeqCst), (onew as usize).wrapping_add(6));
        assert_eq!(COPY_N.load(Ordering::SeqCst), 8);
        assert!(ret.is_null());
        assert_eq!(unsafe { core::ptr::read_unaligned(osrc.wrapping_byte_offset(-8) as *const u32) }, 2);

        // Concat+AddRef lane (src tag==7): AddRef (rc 2→3, inner
        // hook default leaves local alone), same total/copy, then
        // local release (rc 3→2, no dtor); returns null.
        reset();
        arena!(awb, owb, 2, 1, 3);
        arena!(asb, osb, 7, 2, 4);
        arena!(anewb, onewb, 2, 1, 0);
        unsafe { SIZE_BUF.store(onewb as usize, Ordering::SeqCst) };
        let mut s2b: *mut u8 = owb;
        let p2b = &mut s2b as *mut *mut u8 as *mut u8;
        let ret = unsafe { fn_00404f98(p2b, osb) };
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SIZE_ARG.load(Ordering::SeqCst), 7);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_SRC.load(Ordering::SeqCst), osb as usize);
        assert_eq!(COPY_DST.load(Ordering::SeqCst), (onewb as usize).wrapping_add(6));
        assert_eq!(COPY_N.load(Ordering::SeqCst), 8);
        assert!(ret.is_null());
        assert_eq!(unsafe { core::ptr::read_unaligned(osb.wrapping_byte_offset(-8) as *const u32) }, 2);

        // Self lane (src==cur, tag==2): total 3*2=6; self-copy
        // (new, new+6, 6); local null so no release; returns null.
        reset();
        arena!(aw3, ow3, 2, 1, 3);
        arena!(anew3, onew3, 2, 1, 0);
        unsafe { SIZE_BUF.store(onew3 as usize, Ordering::SeqCst) };
        let mut s3: *mut u8 = ow3;
        let p3 = &mut s3 as *mut *mut u8 as *mut u8;
        let ret = unsafe { fn_00404f98(p3, ow3) };
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(SIZE_ARG.load(Ordering::SeqCst), 6);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(COPY_SRC.load(Ordering::SeqCst), onew3 as usize);
        assert_eq!(COPY_DST.load(Ordering::SeqCst), (onew3 as usize).wrapping_add(6));
        assert_eq!(COPY_N.load(Ordering::SeqCst), 6);
        assert!(ret.is_null());

        // Fail lanes: self total 0x40000000<<1 and concat total
        // 3+0x40000000 both set top bits → fail hook, no size.
        reset();
        arena!(af4, of4, 2, 1, 0x4000_0000);
        FAIL_RET.store(0x77, Ordering::SeqCst);
        let mut s4: *mut u8 = of4;
        let p4 = &mut s4 as *mut *mut u8 as *mut u8;
        let ret = unsafe { fn_00404f98(p4, of4) };
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ret as usize, 0x77);
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 0);

        reset();
        arena!(aw5, _ow5, 2, 1, 3);
        arena!(as5, os5, 2, 2, 0x4000_0000);
        let mut s5: *mut u8 = _ow5;
        let p5 = &mut s5 as *mut *mut u8 as *mut u8;
        let ret = unsafe { fn_00404f98(p5, os5) };
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ret as usize, 0x77);
        assert_eq!(SIZE_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(COPY_HITS.load(Ordering::SeqCst), 0);
    }
}
