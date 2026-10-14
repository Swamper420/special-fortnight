//! Original procedure `0x0040d9d8` (78 bytes, `0x0040d9d8–0x0040da25`).
//! Evidence: `evidence/0040d9d8_fn_0040d9d8.md`.

unsafe extern "C" fn default_check(_p1: *mut u32, _p3: *mut u8, _p6: i32) -> i32 {
    1
}

/// Target `0x0040d2bc` (`FUN_0040d2bc`), header check; nonzero return kept.
///
/// ponytail: hook standing in for out-of-batch `fn_0040d2bc`.
pub static mut HOOK_0040D2BC: unsafe extern "C" fn(*mut u32, *mut u8, i32) -> i32 = default_check;

/// Gate on `param_2==0x50`; on check-zero writes size/param outs, returns check result or 1.
/// `param_1` EAX / `param_2` EDX / `param_3` ECX per `__register` observation.
pub unsafe fn fn_0040d9d8(
    param_1: *mut u32,
    param_2: i32,
    param_3: *mut u8,
    param_4: *mut u32,
    param_5: *mut i32,
    param_6: i32,
) -> i32 {
    if param_2 != 0x50 {
        return 1;
    }
    let r = HOOK_0040D2BC(param_1, param_3, param_6);
    if r != 0 {
        return r;
    }
    // ponytail: `ADD ECX,[EBX+4]; SHL EDX,CL` — CL 5-bit mask is CPU behavior; `&0x1f` matches.
    let b0 = core::ptr::read_unaligned(param_1 as *const u8) as u32;
    let b1 = core::ptr::read_unaligned(param_1.wrapping_byte_add(4) as *const u8) as u32;
    let base = 0x300u32.wrapping_shl((b0.wrapping_add(b1)) & 0x1f).wrapping_add(0x736);
    core::ptr::write_unaligned(param_5, base.wrapping_add(base) as i32);
    core::ptr::write_unaligned(
        param_4,
        core::ptr::read_unaligned(param_1.wrapping_byte_add(0xc) as *const u32),
    );
    r
}

#[cfg(test)]
mod tests {
    use super::{HOOK_0040D2BC, fn_0040d9d8};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static RET: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn check(_p1: *mut u32, _p3: *mut u8, _p6: i32) -> i32 {
        HITS.fetch_add(1, Ordering::SeqCst);
        RET.load(Ordering::SeqCst) as i32
    }

    #[test]
    fn gate_and_writes() {
        unsafe { HOOK_0040D2BC = check };
        let mut hdr = [0u32; 4];
        let mut out1 = 0u32;
        let mut out2 = 0i32;
        // Non-0x50: early 1, no hook.
        HITS.store(0, Ordering::SeqCst);
        let r = unsafe { fn_0040d9d8(hdr.as_mut_ptr(), 0x51, core::ptr::null_mut(), &mut out1, &mut out2, 7) };
        assert_eq!(r, 1);
        assert_eq!(HITS.load(Ordering::SeqCst), 0);
        // Hook nonzero: returned as-is, no writes.
        RET.store(5, Ordering::SeqCst);
        HITS.store(0, Ordering::SeqCst);
        out1 = 0;
        out2 = 0;
        let r = unsafe { fn_0040d9d8(hdr.as_mut_ptr(), 0x50, core::ptr::null_mut(), &mut out1, &mut out2, 7) };
        assert_eq!(r, 5);
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!((out1, out2), (0, 0));
        // Hook zero: writes land, returns 0. hdr bytes 0 → ((0x300<<0)+0x736)*2.
        RET.store(0, Ordering::SeqCst);
        hdr[0] = 0;
        hdr[3] = 0x1234;
        let r = unsafe { fn_0040d9d8(hdr.as_mut_ptr(), 0x50, core::ptr::null_mut(), &mut out1, &mut out2, 7) };
        assert_eq!(r, 0);
        assert_eq!(out2, ((0x300 + 0x736) * 2) as i32);
        assert_eq!(out1, 0x1234);
    }
}
