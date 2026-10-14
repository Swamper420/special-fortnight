//! Original procedure `0x0040a3f8` (132 bytes, `0x0040a3f8–0x0040a47b`).
//! Evidence: `evidence/0040a3f8_fn_0040a3f8.md`.

use crate::fn_004046c4::fn_004046c4;
use crate::fn_00404820::fn_00404820;
use crate::fn_0040493c::fn_0040493c;
use crate::fn_00404d24::fn_00404d24;
use crate::fn_0040a3c8::fn_0040a3c8;

/// `local_8=param_1; pin(param_1); if local_8 && tag(local_8-10)!=2
/// { pl=4820(&local_8, local_8) } else { pl=local_8 };
/// w=[pl+idx*2-2]; if surrogate { base=4d24(local_8);
/// measure(base+idx*2-2) }; release(&local_8)`. `param_1` in EAX
/// (object pointer), `param_2` in EDX (1-based wide-char index) per
/// Ghidra `__register` observation. SEH install/teardown omitted
/// (host-incompatible, no host effect). The measure result (ESI) is
/// dead — void return respected. `idx*2` wraps (`ADD EDX,EDX`);
/// `-10`/`-2` offsets sign-extended; address math in `usize`.
///
/// ponytail: direct calls to the four done callees plus the sibling
/// measure; thunks are transparent jumps called through.
pub unsafe fn fn_0040a3f8(param_1: *mut u8, param_2: i32) {
    let mut local_8: *mut u8 = param_1;
    fn_0040493c(param_1);
    let mut pl: *mut u8 = local_8;
    if !local_8.is_null()
        && core::ptr::read_unaligned(local_8.wrapping_byte_offset(-10) as *const u16) != 2
    {
        pl = fn_00404820(
            &mut local_8 as *mut *mut u8 as *mut u32,
            local_8,
        ) as usize as *mut u8;
    }
    let w: u16 = core::ptr::read_unaligned(
        (pl as usize)
            .wrapping_add((param_2 as u32).wrapping_mul(2) as usize)
            .wrapping_sub(2) as *const u16,
    );
    if w >= 0xd800 && w <= 0xdfff {
        let base = fn_00404d24(local_8);
        let q = ((base as usize)
            .wrapping_add((param_2 as u32).wrapping_mul(2) as usize)
            .wrapping_sub(2)) as *const u16;
        fn_0040a3c8(q);
    }
    fn_004046c4(&mut local_8 as *mut *mut u8 as *mut u8);
}

#[cfg(test)]
mod tests {
    use super::fn_0040a3f8;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NORM_HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn norm_callee(_a: *mut u32, _b: *mut u8) {
        NORM_HITS.fetch_add(1, Ordering::SeqCst);
    }

    /// Header arena: obj = base+12; tag u16 @+2 (`obj-10`),
    /// refcount u32 @+4 (`obj-8`), len u32 @+8 (`obj-4`).
    unsafe fn arena(a: &mut [u8; 32], tag: u16, rc: u32, chars: &[u16]) -> *mut u8 {
        let base = a.as_mut_ptr();
        core::ptr::write_unaligned(base.wrapping_add(2) as *mut u16, tag);
        core::ptr::write_unaligned(base.wrapping_add(4) as *mut u32, rc);
        core::ptr::write_unaligned(base.wrapping_add(8) as *mut u32, chars.len() as u32);
        let data = base.wrapping_add(12) as *mut u16;
        for (k, c) in chars.iter().enumerate() {
            core::ptr::write_unaligned(data.wrapping_add(k), *c);
        }
        base.wrapping_add(12)
    }

    unsafe fn rc_of(base: *mut u8) -> u32 {
        core::ptr::read_unaligned(base.wrapping_add(4) as *const u32)
    }

    #[test]
    fn pin_normalize_measure_release_lanes() {
        // Release reads HOOK_00402E20 (owner has TEST_LOCK); the
        // normalize callee owner has none: hold the common lock.
        let _common = crate::fn_004046c4::TEST_LOCK.lock().unwrap();
        let saved = unsafe { crate::fn_00404820::CALLEE_00404E6C };
        unsafe { crate::fn_00404820::CALLEE_00404E6C = norm_callee };

        // Lane A: tag==2 plain char, no normalize; pin+release net zero.
        let mut aa = [0u8; 32];
        let oa = unsafe { arena(&mut aa, 2, 5, &[0x41, 0]) };
        let base_a = unsafe { oa.wrapping_byte_offset(-12) };
        NORM_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040a3f8(oa, 1) };
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { rc_of(base_a) }, 5);

        // Lane B: non-tag plain char, one normalize; net zero.
        let mut ab = [0u8; 32];
        let ob = unsafe { arena(&mut ab, 1, 5, &[0x41, 0]) };
        let base_b = unsafe { ob.wrapping_byte_offset(-12) };
        NORM_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040a3f8(ob, 1) };
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { rc_of(base_b) }, 5);

        // Lane C: surrogate at index 1, measure lane; net zero.
        let mut ac = [0u8; 32];
        let oc = unsafe { arena(&mut ac, 2, 5, &[0xd800, 0xdc00, 0]) };
        let base_c = unsafe { oc.wrapping_byte_offset(-12) };
        NORM_HITS.store(0, Ordering::SeqCst);
        unsafe { fn_0040a3f8(oc, 1) };
        assert_eq!(NORM_HITS.load(Ordering::SeqCst), 0);
        assert_eq!(unsafe { rc_of(base_c) }, 5);

        unsafe { crate::fn_00404820::CALLEE_00404E6C = saved };
    }
}
