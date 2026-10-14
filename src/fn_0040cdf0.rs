//! Original procedure `0x0040cdf0` (49 bytes, `0x0040cdf0–0x0040ce20`).
//! Evidence: `evidence/0040cdf0_fn_0040cdf0.md`.

/// `*p2=base+0x6c; *p3=0;` if `[base+0x10]==0` → indirect `[base+8]` fill.
/// `param_1` EAX / `param_2` EDX / `param_3` ECX per `__register` observation.
pub unsafe fn fn_0040cdf0(param_1: *mut u8, param_2: *mut usize, param_3: *mut i32) {
    core::ptr::write_unaligned(param_2, (param_1 as usize).wrapping_add(0x6c));
    core::ptr::write_unaligned(param_3, 0);
    if core::ptr::read_unaligned(param_1.wrapping_byte_add(0x10) as *const u8) == 0 {
        // ponytail: raw indirect `CALL dword ptr [EBX+8]`; transmute the
        // table word, no hook — target varies per instance.
        let target: usize =
            core::ptr::read_unaligned(param_1.wrapping_byte_add(8) as *const usize);
        let arg0: u32 =
            core::ptr::read_unaligned(param_1.wrapping_byte_add(0xc) as *const u32);
        let f: unsafe extern "C" fn(u32, usize, u32) -> i32 = core::mem::transmute(target);
        let r = f(arg0, (param_1 as usize).wrapping_add(0x6c), 0x10000);
        core::ptr::write_unaligned(param_3, r);
        if r == 0 {
            core::ptr::write_unaligned(param_1.wrapping_byte_add(0x10), 1u8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fn_0040cdf0;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(0);
    static GOT_N: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn stub(_a: u32, _b: usize, n: u32) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        assert_eq!(n, 0x10000);
        GOT_N.store(_b, Ordering::SeqCst);
        RET.load(Ordering::SeqCst) as i32
    }

    #[test]
    fn flag_and_result_lanes() {
        // Flag set: no indirect, outs published.
        let mut rec = [0u8; 0x80];
        let base = rec.as_mut_ptr();
        let mut p2: usize = 0;
        let mut p3: i32 = 9;
        unsafe {
            // ponytail: `+8` (8 B indirect word on host) overlaps `+0xc`;
            // write the dword first so the indirect word stays intact
            // (stub ignores the arg lane).
            core::ptr::write_unaligned(base.wrapping_byte_add(0xc) as *mut u32, 0x11);
            core::ptr::write_unaligned(
                base.wrapping_byte_add(8) as *mut usize,
                stub as usize,
            );
            core::ptr::write_unaligned(base.wrapping_byte_add(0x10), 1u8);
            fn_0040cdf0(base, &mut p2, &mut p3);
        }
        assert_eq!(p2, (base as usize).wrapping_add(0x6c));
        assert_eq!(p3, 0);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        // Flag clear, nonzero result: stored, flag untouched.
        RET.store(4, Ordering::SeqCst);
        unsafe {
            core::ptr::write_unaligned(base.wrapping_byte_add(0x10), 0u8);
            fn_0040cdf0(base, &mut p2, &mut p3);
        }
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(GOT_N.load(Ordering::SeqCst), (base as usize).wrapping_add(0x6c));
        assert_eq!(p3, 4);
        unsafe {
            assert_eq!(core::ptr::read_unaligned(base.wrapping_byte_add(0x10) as *const u8), 0);
        }
        // Flag clear, zero result: flag set.
        RET.store(0, Ordering::SeqCst);
        unsafe {
            fn_0040cdf0(base, &mut p2, &mut p3);
        }
        assert_eq!(p3, 0);
        unsafe {
            assert_eq!(core::ptr::read_unaligned(base.wrapping_byte_add(0x10) as *const u8), 1);
        }
    }
}
