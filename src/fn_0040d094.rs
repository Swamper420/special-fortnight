//! Original procedure `0x0040d094` (136 bytes, `0x0040d094–0x0040d11b`).
//! Evidence: `evidence/0040d094_fn_0040d094.md`.

unsafe extern "C" fn default_next(_b: *mut u8, _p2: u32, _p3: i32) -> u8 {
    0
}

/// Target `0x0040cfb4` (`FUN_0040cfb4`), both renormalize sites.
///
/// ponytail: hook standing in for same-batch `fn_0040cfb4`.
pub static mut HOOK_0040CFB4: unsafe extern "C" fn(*mut u8, u32, i32) -> u8 = default_next;

/// Bit-probability decode; returns 0 (`bound>code` strict) or 1.
/// `param_1` EAX / `param_2` EDX per `__register` observation.
pub unsafe fn fn_0040d094(param_1: *mut u16, param_2: *mut u8) -> u32 {
    let prob: u16 = core::ptr::read_unaligned(param_1);
    let range: u32 = core::ptr::read_unaligned(param_2.wrapping_byte_add(8) as *const u32);
    // ponytail: `SHR 11` then `IMUL`; `wrapping_mul` matches target wrap.
    let bound: u32 = (range >> 0xb).wrapping_mul(prob as u32);
    let code: u32 = core::ptr::read_unaligned(param_2.wrapping_byte_add(0xc) as *const u32);
    if code <= bound && bound.wrapping_sub(code) != 0 {
        core::ptr::write_unaligned(param_2.wrapping_byte_add(8) as *mut u32, bound);
        let v: u16 = core::ptr::read_unaligned(param_1);
        // ponytail: `(0x800 - v) >> 5` arithmetic; `as i32` then `SAR`.
        let step: i32 = ((0x800u32.wrapping_sub(v as u32)) as i32) >> 5;
        core::ptr::write_unaligned(param_1, v.wrapping_add(step as u16));
        if core::ptr::read_unaligned(param_2.wrapping_byte_add(8) as *const u32) < 0x1000000 {
            let b = HOOK_0040CFB4(param_2, v as u32, step);
            let c: u32 = core::ptr::read_unaligned(param_2.wrapping_byte_add(0xc) as *const u32);
            core::ptr::write_unaligned(
                param_2.wrapping_byte_add(0xc) as *mut u32,
                (b as u32) | c.wrapping_shl(8),
            );
            let r: u32 = core::ptr::read_unaligned(param_2.wrapping_byte_add(8) as *const u32);
            core::ptr::write_unaligned(param_2.wrapping_byte_add(8) as *mut u32, r.wrapping_shl(8));
        }
        return 0;
    }
    core::ptr::write_unaligned(
        param_2.wrapping_byte_add(8) as *mut u32,
        range.wrapping_sub(bound),
    );
    core::ptr::write_unaligned(
        param_2.wrapping_byte_add(0xc) as *mut u32,
        code.wrapping_sub(bound),
    );
    let v2: u16 = core::ptr::read_unaligned(param_1);
    core::ptr::write_unaligned(param_1, v2.wrapping_sub((v2 as u32 >> 5) as u16));
    if core::ptr::read_unaligned(param_2.wrapping_byte_add(8) as *const u32) < 0x1000000 {
        let b = HOOK_0040CFB4(param_2, (v2 as u32) >> 5, prob as u32 as i32);
        let c: u32 = core::ptr::read_unaligned(param_2.wrapping_byte_add(0xc) as *const u32);
        core::ptr::write_unaligned(
            param_2.wrapping_byte_add(0xc) as *mut u32,
            (b as u32) | c.wrapping_shl(8),
        );
        let r: u32 = core::ptr::read_unaligned(param_2.wrapping_byte_add(8) as *const u32);
        core::ptr::write_unaligned(param_2.wrapping_byte_add(8) as *mut u32, r.wrapping_shl(8));
    }
    1
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040CFB4, fn_0040d094};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn next(_b: *mut u8, _p2: u32, _p3: i32) -> u8 {
        HITS.fetch_add(1, Ordering::SeqCst);
        0x11
    }

    fn state(range: u32, code: u32) -> [u8; 16] {
        let mut s = [0u8; 16];
        unsafe {
            core::ptr::write_unaligned(s.as_mut_ptr().wrapping_byte_add(8) as *mut u32, range);
            core::ptr::write_unaligned(s.as_mut_ptr().wrapping_byte_add(0xc) as *mut u32, code);
        }
        s
    }

    #[test]
    fn zero_and_one_lanes() {
        unsafe { HOOK_0040CFB4 = next };
        // Zero lane: range 0x1000000>>11=0x800 *prob 0x400 = 0x200000 > code 0x10.
        HITS.store(0, Ordering::SeqCst);
        let mut prob: u16 = 0x400;
        let mut st = state(0x1000000, 0x10);
        let r = unsafe { fn_0040d094(&mut prob, st.as_mut_ptr()) };
        assert_eq!(r, 0);
        assert!(prob > 0x400); // adapted up
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        // One lane: bound==0 (range small) → else branch.
        HITS.store(0, Ordering::SeqCst);
        let mut prob: u16 = 0x400;
        let mut st = state(0x100, 0x200);
        let r = unsafe { fn_0040d094(&mut prob, st.as_mut_ptr()) };
        assert_eq!(r, 1);
        assert!(prob < 0x400); // adapted down
    }
}
