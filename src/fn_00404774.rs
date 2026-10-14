//! Original procedure `0x00404774` (74 bytes, `0x00404774–0x004047bd`).
//! Evidence: `evidence/00404774_fn_00404774.md`.

unsafe extern "C" fn default_alloc(_size: u32) -> *mut u8 {
    core::ptr::null_mut()
}

unsafe extern "C" fn default_fail(_arg: u32) -> *mut u8 {
    core::ptr::null_mut()
}

/// Allocator `0x00402e04` (`FUN_00402e04`), arg is evened `len+14`.
///
/// ponytail: hook standing in for done `fn_00402e04` (which takes/returns
/// `i32`), rewire to real call once cross-module test serialization exists.
pub static mut ALLOC_00402E04: unsafe extern "C" fn(u32) -> *mut u8 = default_alloc;

/// Overflow arm `0x0040380c` (`thunk_FUN_00402f60`), terminal `JMP` with the
/// wrapped `len+14`.
///
/// ponytail: hook standing in for unreconstructed target; call+return
/// models the `JMP` per decompiler, diverge-only-if-noreturn.
pub static mut FAIL_00402F60: unsafe extern "C" fn(u32) -> *mut u8 = default_fail;

/// Default codeword observed as `dword ptr [0x004138c8]`.
///
/// ponytail: absolute-address cell as hermetic own-module static, unify
/// with writer modules in `data.rs` once data layout proven.
pub static mut DAT_004138C8: u32 = 0;

/// Allocate a 12-byte-header string, return data pointer (`base+12`).
/// `param_1` (length) arrives in EAX signed, `param_2` (codeword) in EDX.
/// Size is `(len+14) & ~1`; carry on the `+14` takes the fail arm.
pub unsafe fn fn_00404774(param_1: i32, param_2: u32) -> *mut u8 {
    if param_1 < 1 {
        return core::ptr::null_mut();
    }
    let bumped = (param_1 as u32).wrapping_add(0xe);
    if bumped < param_1 as u32 {
        return FAIL_00402F60(bumped);
    }
    let size = bumped & 0xfffffffe;
    let base = ALLOC_00402E04(size);
    *((base as usize).wrapping_add((size.wrapping_sub(2)) as usize) as *mut u16) = 0;
    let data = base.wrapping_add(12);
    *((data as usize).wrapping_sub(4) as *mut u32) = param_1 as u32;
    *((data as usize).wrapping_sub(8) as *mut u32) = 1;
    let mut cp = param_2;
    if cp == 0 {
        cp = DAT_004138C8;
    }
    *((data as usize).wrapping_sub(12) as *mut u16) = cp as u16;
    *((data as usize).wrapping_sub(10) as *mut u16) = 1;
    data
}

#[cfg(test)]
mod tests {
    use super::{ALLOC_00402E04, DAT_004138C8, FAIL_00402F60, fn_00404774};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ALLOC_HITS: AtomicUsize = AtomicUsize::new(0);
    static ALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);
    static FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
    static mut BACKING: [u8; 64] = [0; 64];

    unsafe extern "C" fn alloc(size: u32) -> *mut u8 {
        ALLOC_HITS.fetch_add(1, Ordering::SeqCst);
        ALLOC_SIZE.store(size as usize, Ordering::SeqCst);
        BACKING.as_mut_ptr()
    }

    unsafe extern "C" fn fail(_arg: u32) -> *mut u8 {
        FAIL_HITS.fetch_add(1, Ordering::SeqCst);
        core::ptr::null_mut()
    }

    #[test]
    fn alloc_header_sizes() {
        unsafe {
            ALLOC_00402E04 = alloc;
            FAIL_00402F60 = fail;
            DAT_004138C8 = 0x22;
        }
        // Guard: len < 1 → null, no alloc, no fail.
        ALLOC_HITS.store(0, Ordering::SeqCst);
        FAIL_HITS.store(0, Ordering::SeqCst);
        assert!(unsafe { fn_00404774(0, 0) }.is_null());
        assert!(unsafe { fn_00404774(-3, 0) }.is_null());
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(FAIL_HITS.load(Ordering::SeqCst), 0);

        // len=1 → size (1+14)&~1 = 14; header init; return base+12.
        ALLOC_HITS.store(0, Ordering::SeqCst);
        let d = unsafe { fn_00404774(1, 0x33) };
        assert_eq!(ALLOC_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(ALLOC_SIZE.load(Ordering::SeqCst), 14);
        let base = unsafe { BACKING.as_mut_ptr() } as usize;
        assert_eq!(d as usize, base.wrapping_add(12));
        unsafe {
            assert_eq!(*(base as *const u16), 0x33);
            assert_eq!(*((base.wrapping_add(2)) as *const u16), 1);
            assert_eq!(*((base.wrapping_add(4)) as *const u32), 1);
            assert_eq!(*((base.wrapping_add(8)) as *const u32), 1);
            assert_eq!(*((base.wrapping_add(12)) as *const u16), 0);
        }

        // len=5 → size 19&~1 = 18; cp 0 substitutes DAT_004138c8.
        let d = unsafe { fn_00404774(5, 0) };
        assert_eq!(ALLOC_SIZE.load(Ordering::SeqCst), 18);
        assert_eq!(d as usize, base.wrapping_add(12));
        unsafe {
            assert_eq!(*(base as *const u16), 0x22);
            assert_eq!(*((base.wrapping_add(8)) as *const u32), 5);
            assert_eq!(*((base.wrapping_add(16)) as *const u16), 0);
        }
    }
}
