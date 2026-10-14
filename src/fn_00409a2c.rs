//! Original procedure `0x00409a2c` (39 bytes, `0x409a2c–0x409a52`).
//! Evidence: `evidence/00409a2c_fn_00409a2c.md`.

unsafe extern "C" fn default_query() -> *const u8 {
    core::ptr::null()
}

unsafe extern "C" fn default_match(_p: *const u8, _key: u32) -> u32 {
    0
}

unsafe extern "C" fn default_take() -> u32 {
    0
}

/// Target `0x402e88` (`FUN_00402e88`), no args; result feeds the
/// match call as its object.
///
/// ponytail: hook standing in for done `fn_00402e88` (which
/// returns the DATA pointer), rewire to the real call once
/// cross-module linkage proven.
pub static mut HOOK_00402e88: unsafe extern "C" fn() -> *const u8 = default_query;

/// Target `0x40392c` (`FUN_0040392c`), `(query, [0x406d5c])`;
/// only the low byte of the result is tested.
///
/// ponytail: hook standing in for done `fn_0040392c`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_0040392c: unsafe extern "C" fn(*const u8, u32) -> u32 = default_match;

/// Target `0x402ec8` (`FUN_00402ec8`), no args; result stored to
/// `[param_1+0xc]`.
///
/// ponytail: hook standing in for done `fn_00402ec8`, rewire to
/// the real call once cross-module linkage proven.
pub static mut HOOK_00402ec8: unsafe extern "C" fn() -> u32 = default_take;

/// Dword VALUE at absolute `0x406d5c` (`PTR_PTR_00406d5c`,
/// nominally `PTR_LAB_00406db4`), passed by value as the match
/// key (no dereference at this site).
///
/// ponytail: absolute-address cell modeled as mutable seed
/// static, upgrade to real image-relative import once data layout
/// proven.
pub static mut DATA_00406D5C: u32 = 0;

/// `if [p+0x14]!=0 { r=match(query(), [0x406d5c]);
/// if (r&0xff)!=0 { [p+0xc]=take() } }`. `p1` arrives in EAX
/// (saved to EBX, the store base) per Ghidra `__register`
/// observation. Flag is one byte, slot one dword per observed
/// widths.
pub unsafe fn fn_00409a2c(param_1: *mut u8) {
    if core::ptr::read_unaligned(param_1.wrapping_byte_add(0x14) as *const u8) == 0 {
        return;
    }
    let q = HOOK_00402e88();
    let r = HOOK_0040392c(q, DATA_00406D5C);
    if r & 0xff == 0 {
        return;
    }
    let v = HOOK_00402ec8();
    core::ptr::write_unaligned(param_1.wrapping_byte_add(0xc) as *mut u32, v);
}

#[cfg(test)]
mod tests {
    use super::{DATA_00406D5C, HOOK_00402e88, HOOK_0040392c, HOOK_00402ec8, fn_00409a2c};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static Q_HITS: AtomicUsize = AtomicUsize::new(0);
    static Q_RET: AtomicUsize = AtomicUsize::new(0);
    static M_HITS: AtomicUsize = AtomicUsize::new(0);
    static M_P: AtomicUsize = AtomicUsize::new(0);
    static M_KEY: AtomicUsize = AtomicUsize::new(0);
    static M_RET: AtomicUsize = AtomicUsize::new(0);
    static T_HITS: AtomicUsize = AtomicUsize::new(0);
    static T_RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn query() -> *const u8 {
        Q_HITS.fetch_add(1, Ordering::SeqCst);
        Q_RET.load(Ordering::SeqCst) as *const u8
    }

    unsafe extern "C" fn match_fn(p: *const u8, key: u32) -> u32 {
        M_HITS.fetch_add(1, Ordering::SeqCst);
        M_P.store(p as usize, Ordering::SeqCst);
        M_KEY.store(key as usize, Ordering::SeqCst);
        M_RET.load(Ordering::SeqCst) as u32
    }

    unsafe extern "C" fn take() -> u32 {
        T_HITS.fetch_add(1, Ordering::SeqCst);
        T_RET.load(Ordering::SeqCst) as u32
    }

    fn reset() {
        Q_HITS.store(0, Ordering::SeqCst);
        M_HITS.store(0, Ordering::SeqCst);
        T_HITS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn flag_miss_and_hit_lanes() {
        unsafe {
            HOOK_00402e88 = query;
            HOOK_0040392c = match_fn;
            HOOK_00402ec8 = take;
            DATA_00406D5C = 0x0db4;
        }
        let obj_buf = [0u8; 8];
        let inner = obj_buf.as_ptr();
        Q_RET.store(inner as usize, Ordering::SeqCst);
        // Feasible buffer: flag at +0x14, slot at +0xc.
        let mut buf = [0u8; 0x18];
        let p = buf.as_mut_ptr();
        // Flag-zero lane: nothing fires, slot kept.
        reset();
        unsafe {
            *p.wrapping_byte_add(0x14) = 0;
            *p.wrapping_byte_add(0xc).cast::<u32>() = 0x1111_1111;
            fn_00409a2c(p);
            assert_eq!(*p.wrapping_byte_add(0xc).cast::<u32>(), 0x1111_1111);
        }
        assert_eq!(Q_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(M_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(T_HITS.load(Ordering::SeqCst), 0);
        // Miss lane: low byte zero → no take, slot kept.
        reset();
        M_RET.store(0x1234_5600, Ordering::SeqCst);
        unsafe {
            *p.wrapping_byte_add(0x14) = 1;
            fn_00409a2c(p);
            assert_eq!(*p.wrapping_byte_add(0xc).cast::<u32>(), 0x1111_1111);
        }
        assert_eq!(Q_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(M_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(M_P.load(Ordering::SeqCst), inner as usize);
        assert_eq!(M_KEY.load(Ordering::SeqCst), 0x0db4);
        assert_eq!(T_HITS.load(Ordering::SeqCst), 0);
        // Hit lane: low byte nonzero → take stored.
        reset();
        M_RET.store(0x1234_5601, Ordering::SeqCst);
        T_RET.store(0x9e37_79b9, Ordering::SeqCst);
        unsafe {
            fn_00409a2c(p);
            assert_eq!(*p.wrapping_byte_add(0xc).cast::<u32>(), 0x9e37_79b9);
        }
        assert_eq!(T_HITS.load(Ordering::SeqCst), 1);
    }
}
