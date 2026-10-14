//! Original procedure `0x0040633c` (134 bytes, `0x0040633c–0x004063c1`).
//! Evidence: `evidence/0040633c_fn_0040633c.md`.

/// Target `0x00404d24` (`FUN_00404d24`): rewired to
/// `crate::fn_00404d24::fn_00404d24` (signatures match exactly).
use crate::fn_00404d24::fn_00404d24;

unsafe extern "C" fn default_convert(
    _dst: *mut u16,
    _cap: u32,
    _src: *const u8,
    _n: i32,
) -> u32 {
    0
}

unsafe extern "C" fn default_release(_slot: *mut u8) {}

/// Target `0x00404c98` (`FUN_00404c98`), `(param_2, null)` on entry,
/// `(param_2, local)` after the convert lanes: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut u8, *mut u8)`).

/// Target `0x00404f00` (`FUN_00404f00`), `(&local_8, lead)` then
/// `(&local_8, n-1)` on the positive lane: direct
/// intra-reconstruction call (rewired; signatures verified
/// `fn(*mut *mut u8, u32)`). Its alloc/normalize/realloc/fail
/// hooks stay, pinned by the test under the owner lock.

/// Target `0x004062b8` (`FUN_004062b8`),
/// `(data, lead+1, param_1+1, lead)`; 4th arg spilled with `PUSH EBX`
/// at `0x00406371` across the data call.
///
/// ponytail: hook standing in for done `fn_004062b8`, rewire to the
/// real call once cross-module linkage proven.
pub static mut HOOK_004062b8: unsafe extern "C" fn(*mut u16, u32, *const u8, i32) -> u32 =
    default_convert;

/// Target `0x00404cec` (`FUN_00404cec`), `(&local_8, null)` on the
/// signed-`JLE` (`n<=0`) lane: direct intra-reconstruction call
/// (rewired; signatures verified `fn(*mut u8, *mut u8)`).

/// Target `0x00404c88` (`thunk_FUN_004046c4`), always run on
/// `&local_8` (SEH finally on target); return ignored, as at site.
///
/// ponytail: hook standing in for the thunk target, rewire once
/// `0x004046c4` is linked.
pub static mut HOOK_004046c4: unsafe extern "C" fn(*mut u8) = default_release;

/// Lead-byte convert: `pin(param_2, null)`; if `*param_1 != 0`,
/// `ensure(&local, lead)`, `convert(data(local), lead+1,
/// param_1+1, lead)`, then signed-`JLE` selects `cec(&local, null)`
/// vs `ensure(&local, n-1)`, `pin(param_2, local)`; always
/// `release(&local)`. `param_1` EAX / `param_2` EDX per Ghidra
/// `__register` observation. `FS:[0]` SEH setup/teardown omitted
/// (host-incompatible); always-run release kept. Positive strides
/// use `wrapping_byte_add`; `DEC`/`+1` wrap.
pub unsafe fn fn_0040633c(param_1: *const u8, param_2: *mut u8) {
    let mut local_8: *mut u8 = core::ptr::null_mut();
    crate::fn_00404c98::fn_00404c98(param_2, core::ptr::null_mut());
    if core::ptr::read_unaligned(param_1) != 0 {
        let lead: u32 = core::ptr::read_unaligned(param_1) as u32;
        crate::fn_00404f00::fn_00404f00(&mut local_8 as *mut *mut u8, lead);
        let data: *const u8 = fn_00404d24(local_8 as *const u8);
        let n: u32 = HOOK_004062b8(
            data as *mut u16,
            lead.wrapping_add(1),
            (param_1 as usize).wrapping_add(1) as *const u8,
            lead as i32,
        );
        if (n as i32) <= 0 {
            crate::fn_00404cec::fn_00404cec(
                &mut local_8 as *mut *mut u8 as *mut u8,
                core::ptr::null_mut(),
            );
        } else {
            crate::fn_00404f00::fn_00404f00(&mut local_8 as *mut *mut u8, n.wrapping_sub(1));
        }
        crate::fn_00404c98::fn_00404c98(param_2, local_8);
    }
    HOOK_004046c4(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::{HOOK_004046c4, HOOK_004062b8, fn_0040633c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_ARG: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_SEQ: AtomicUsize = AtomicUsize::new(0);
    static NORM_HITS: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static CVT_HITS: AtomicUsize = AtomicUsize::new(0);
    static CVT_DST: AtomicUsize = AtomicUsize::new(0);
    static CVT_CAP: AtomicUsize = AtomicUsize::new(0);
    static CVT_SRC: AtomicUsize = AtomicUsize::new(0);
    static CVT_N: AtomicUsize = AtomicUsize::new(0);
    static CVT_RET: AtomicUsize = AtomicUsize::new(0);
    static REL_HITS: AtomicUsize = AtomicUsize::new(0);

    /// Headed store target for the real `fn_00404c98` lane: tag 2,
    /// refcount reset per lane, length 0.
    static mut OBJ_ARENA: [u8; 64] = [0; 64];

    unsafe fn obj() -> *mut u8 {
        let base = core::ptr::addr_of_mut!(OBJ_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 0);
        base.wrapping_byte_add(12)
    }

    unsafe fn rc_of(p: *mut u8) -> u32 {
        core::ptr::read_unaligned(p.wrapping_byte_offset(-8) as *const u32)
    }

    unsafe fn slot_val(slot: *mut u8) -> usize {
        core::ptr::read_unaligned(slot as *const usize)
    }

    /// Headed second object for the positive lane's second
    /// ensure (first ensure takes the first, so the store observes
    /// a fresh take).
    static mut OBJ_B_ARENA: [u8; 64] = [0; 64];

    unsafe fn obj_b() -> *mut u8 {
        let base = core::ptr::addr_of_mut!(OBJ_B_ARENA) as *mut u8;
        core::ptr::write_unaligned(base.wrapping_byte_add(2) as *mut u16, 2);
        core::ptr::write_unaligned(base.wrapping_byte_add(4) as *mut u32, 5);
        core::ptr::write_unaligned(base.wrapping_byte_add(8) as *mut u32, 0);
        base.wrapping_byte_add(12)
    }

    /// Real `fn_00404f00`'s alloc hook behind both ensures (null
    /// slot first: no normalize/realloc; second: old released by
    /// the real call, fresh object stored).
    unsafe extern "C" fn alloc(n: u32) -> *mut u8 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_ARG.store(n as usize, Ordering::SeqCst);
        if ALLOC_SEQ.fetch_add(1, Ordering::SeqCst) == 0 {
            obj()
        } else {
            obj_b()
        }
    }

    unsafe extern "C" fn normalize(_out: *mut u8, _src: *mut u8) {
        NORM_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn realloc(_slot: *mut *mut u8, _total: u32) {
        REALLOC_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn fail(_base: *mut u8) {
        FAIL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn convert(dst: *mut u16, cap: u32, src: *const u8, n: i32) -> u32 {
        CVT_HITS.fetch_add(1, Ordering::SeqCst);
        CVT_DST.store(dst as usize, Ordering::SeqCst);
        CVT_CAP.store(cap as usize, Ordering::SeqCst);
        CVT_SRC.store(src as usize, Ordering::SeqCst);
        CVT_N.store(n as usize, Ordering::SeqCst);
        CVT_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn release(_slot: *mut u8) {
        REL_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn reset() {
        ALLOC_HITS.store(0, Ordering::SeqCst);
        ALLOC_SEQ.store(0, Ordering::SeqCst);
        NORM_HITS.store(0, Ordering::SeqCst);
        REALLOC_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        CVT_HITS.store(0, Ordering::SeqCst);
        REL_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn null_convert_zero_convert_positive_lanes() {
        // Real `fn_00404c98` behind both pins (null old → no dtor)
        // and real `fn_00404cec` behind the convert-zero lane (its
        // dtor lane reaches done `fn_00402e20`): hold the common
        // owner lock and the dtor lock.
        let _owner = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let _callee = crate::fn_00402e20::TEST_LOCK.lock().unwrap();
        unsafe {
            crate::fn_00404f00::HOOK_004054b4 = alloc;
            crate::fn_00404f00::HOOK_00404e6c = normalize;
            crate::fn_00404f00::HOOK_00402e38 = realloc;
            crate::fn_00404f00::FAIL_00402F60 = fail;
            HOOK_004062b8 = convert;
            HOOK_004046c4 = release;
        }
        let mut slot = [0u8; 8];
        let param_2 = slot.as_mut_ptr();
        // Null lane: entry pin + release only.
        reset();
        let b0 = [0u8];
        unsafe { fn_0040633c(b0.as_ptr(), param_2) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(CVT_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { slot_val(param_2) }, 0);
        // Convert-zero lane: ensure(3), real 00404d24 passes local
        // through so convert sees the headed obj; convert(.,4,p1+1,3)=0
        // -> real cec(&local, null) releases the headed obj (rc 5→4)
        // and nulls the slot, so the real store takes null.
        reset();
        let b3 = [3u8, 0x41];
        CVT_RET.store(0, Ordering::SeqCst);
        let obj0 = unsafe { obj() };
        unsafe { fn_0040633c(b3.as_ptr(), param_2) };
        // Real first ensure: alloc(3) on the null slot (no
        // normalize/realloc), headed object stored.
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 3);
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(CVT_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(CVT_DST.load(Ordering::SeqCst), obj0 as usize);
        assert_eq!(CVT_CAP.load(Ordering::SeqCst), 4);
        assert_eq!(
            CVT_SRC.load(Ordering::SeqCst),
            (b3.as_ptr() as usize).wrapping_add(1)
        );
        assert_eq!(CVT_N.load(Ordering::SeqCst), 3);
        assert_eq!(unsafe { slot_val(param_2) }, 0);
        assert_eq!(unsafe { rc_of(obj0) }, 4);
        // Convert-positive lane: ensure(2), convert=5 -> ensure(4).
        reset();
        let b2 = [2u8, 0x42];
        CVT_RET.store(5, Ordering::SeqCst);
        let obj1 = unsafe { obj_b() };
        unsafe { fn_0040633c(b2.as_ptr(), param_2) };
        // Real ensures: alloc(2) then alloc(4); the second takes
        // the fresh object (old released 5→4 by the real call),
        // the real store takes it (5→6).
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(ALLOC_ARG.load(Ordering::SeqCst), 4);
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(REALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { slot_val(param_2) }, obj1 as usize);
        assert_eq!(unsafe { rc_of(obj1) }, 6);
        assert_eq!(REL_HITS.load(Ordering::SeqCst), 1);
    }
}
